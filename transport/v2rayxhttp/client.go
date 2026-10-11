package v2rayxhttp

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

// Client implements the client side of Xray's xhttp (splithttp) transport.
//
// P1 supports the `stream-one` mode only: a single request whose body carries the uplink and
// whose response body carries the downlink. This is the mode Xray picks automatically for
// REALITY connections without `download_settings`, which is the common case.
type Client struct {
	// uplink
	uploadURL    url.URL
	uploadClient *http.Client
	uploadHost   string
	// downlink — may point at a different server (Xray's downloadSettings)
	downloadURL    url.URL
	downloadClient *http.Client
	downloadHost   string

	headers http.Header
	method  string
	mode    string
	noGRPC  bool

	paddingFrom int
	paddingTo   int
	paddingKey  string
	paddingHdr  string
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (*Client, error) {
	uploadURL, uploadHost, err := buildRequestURL(serverAddr, options.Host, options.Path, tlsConfig)
	if err != nil {
		return nil, err
	}
	uploadClient, err := newHTTPClient(dialer, serverAddr, tlsConfig)
	if err != nil {
		return nil, err
	}

	// Downlink may use a different server (Xray's downloadSettings).
	downloadURL, downloadHost, downloadClient := uploadURL, uploadHost, uploadClient
	if options.DownloadSettings != nil {
		settings := options.DownloadSettings
		downloadAddr := M.ParseSocksaddrHostPort(settings.Server, settings.Port)
		var downloadTLSConfig tls.Config
		if settings.TLS != nil {
			downloadTLSConfig, err = tls.NewClient(ctx, log.NewNOPFactory().Logger(), settings.Server, *settings.TLS)
			if err != nil {
				return nil, E.Cause(err, "build download tls config")
			}
		}
		downloadURL, downloadHost, err = buildRequestURL(downloadAddr, settings.Host, settings.Path, downloadTLSConfig)
		if err != nil {
			return nil, err
		}
		downloadClient, err = newHTTPClient(dialer, downloadAddr, downloadTLSConfig)
		if err != nil {
			return nil, err
		}
	}

	headers := make(http.Header)
	for key, value := range options.Headers {
		headers[key] = value
	}

	method := options.UplinkHTTPMethod
	if method == "" {
		method = http.MethodPost
	}

	mode := options.Mode
	if mode == "" || mode == "auto" {
		if options.DownloadSettings != nil {
			mode = "stream-up"
		} else {
			mode = "stream-one"
		}
	}

	paddingFrom, paddingTo := 100, 1000
	if options.XPaddingBytes != "" {
		parts := strings.SplitN(options.XPaddingBytes, "-", 2)
		if parsed, parseErr := strconv.Atoi(strings.TrimSpace(parts[0])); parseErr == nil {
			paddingFrom = parsed
			paddingTo = parsed
		}
		if len(parts) == 2 {
			if parsed, parseErr := strconv.Atoi(strings.TrimSpace(parts[1])); parseErr == nil {
				paddingTo = parsed
			}
		}
	}

	paddingKey := options.XPaddingKey
	if paddingKey == "" {
		paddingKey = "x_padding"
	}
	paddingHeader := options.XPaddingHeader
	if paddingHeader == "" {
		paddingHeader = "Referer"
	}

	return &Client{
		uploadURL:      uploadURL,
		uploadClient:   uploadClient,
		uploadHost:     uploadHost,
		downloadURL:    downloadURL,
		downloadClient: downloadClient,
		downloadHost:   downloadHost,
		headers:        headers,
		method:         method,
		mode:           mode,
		noGRPC:         options.NoGRPCHeader,
		paddingFrom:    paddingFrom,
		paddingTo:      paddingTo,
		paddingKey:     paddingKey,
		paddingHdr:     paddingHeader,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if c.mode == "stream-up" {
		return c.dialStreamUp(ctx)
	}
	return c.dialStreamOne(ctx)
}

// dialStreamOne opens a single request: the request body carries the uplink and the response body
// carries the downlink. Xray picks this mode for REALITY connections without download_settings.
func (c *Client) dialStreamOne(ctx context.Context) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := c.newRequest(ctx, c.method, c.uploadURL, c.uploadHost, pipeReader)
	if !c.noGRPC {
		request.Header.Set("Content-Type", "application/grpc")
	}
	c.applyXPadding(request, c.uploadURL)

	reader := &waitReader{wait: make(chan struct{})}
	gotConn := make(chan struct{})
	var remoteAddr, localAddr net.Addr
	var gotConnOnce sync.Once
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			remoteAddr = info.Conn.RemoteAddr()
			localAddr = info.Conn.LocalAddr()
			gotConnOnce.Do(func() { close(gotConn) })
		},
	}))

	go func() {
		response, err := c.uploadClient.Do(request)
		if err != nil {
			reader.closeWith(err)
			pipeReader.CloseWithError(err)
			gotConnOnce.Do(func() { close(gotConn) })
			return
		}
		if response.StatusCode != http.StatusOK {
			reader.closeWith(E.New("unexpected status: ", response.Status))
			response.Body.Close()
			pipeReader.Close()
			return
		}
		reader.set(response.Body)
	}()

	select {
	case <-gotConn:
	case <-ctx.Done():
		pipeReader.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
	return &Conn{
		reader:     reader,
		writer:     pipeWriter,
		pipeReader: pipeReader,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}, nil
}

// dialStreamUp opens two requests that the server correlates by session id: a GET carrying the
// downlink and a long-lived POST carrying the uplink. The downlink may use a different server.
func (c *Client) dialStreamUp(ctx context.Context) (net.Conn, error) {
	sessionID := generateSessionID()

	// uplink first: a single request whose body never ends until the connection closes
	uploadPipeReader, uploadPipeWriter := io.Pipe()
	uploadRequest := c.newRequest(ctx, c.method, withSession(c.uploadURL, sessionID), c.uploadHost, uploadPipeReader)
	if !c.noGRPC {
		uploadRequest.Header.Set("Content-Type", "application/grpc")
	}
	c.applyXPadding(uploadRequest, c.uploadURL)

	uploadDone := make(chan error, 1)
	go func() {
		response, err := c.uploadClient.Do(uploadRequest)
		if err != nil {
			uploadDone <- err
			return
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		uploadDone <- nil
	}()

	// downlink: a GET whose response body is the stream
	downloadRequest := c.newRequest(ctx, http.MethodGet, withSession(c.downloadURL, sessionID), c.downloadHost, nil)
	c.applyXPadding(downloadRequest, c.downloadURL)
	response, err := c.downloadClient.Do(downloadRequest)
	if err != nil {
		uploadPipeReader.CloseWithError(err)
		return nil, E.Cause(err, "open download stream")
	}
	if response.StatusCode != http.StatusOK {
		uploadPipeReader.CloseWithError(E.New("unexpected status: ", response.Status))
		response.Body.Close()
		return nil, E.New("unexpected status: ", response.Status)
	}

	downlinkReader := &waitReader{wait: make(chan struct{})}
	downlinkReader.set(response.Body)
	conn := &Conn{
		reader:     downlinkReader,
		writer:     uploadPipeWriter,
		pipeReader: uploadPipeReader,
	}
	go func() {
		if uploadErr := <-uploadDone; uploadErr != nil {
			conn.Close()
		}
	}()
	return conn, nil
}

func (c *Client) newRequest(ctx context.Context, method string, requestURL url.URL, host string, body io.ReadCloser) *http.Request {
	return (&http.Request{
		Method: method,
		URL:    &requestURL,
		Host:   host,
		Header: c.headers.Clone(),
		Body:   body,
	}).WithContext(context.WithoutCancel(ctx))
}

func (c *Client) applyXPadding(request *http.Request, baseURL url.URL) {
	if c.paddingTo <= 0 {
		return
	}
	length := c.paddingFrom
	if c.paddingTo > c.paddingFrom {
		length += rand.IntN(c.paddingTo - c.paddingFrom)
	}
	if length <= 0 {
		return
	}
	paddingURL := baseURL
	query := paddingURL.Query()
	query.Set(c.paddingKey, strings.Repeat("X", length))
	paddingURL.RawQuery = query.Encode()
	request.Header.Set(c.paddingHdr, paddingURL.String())
}

// buildRequestURL derives the request URL and Host header for a server, mirroring Xray's
// GetNormalizedPath(): the default session/seq placement is `path`, so the path keeps a trailing
// slash and the server matches it with HasPrefix.
func buildRequestURL(serverAddr M.Socksaddr, host string, path string, tlsConfig tls.Config) (url.URL, string, error) {
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = serverAddr.String()
	if err := sHTTP.URLSetPath(&requestURL, path); err != nil {
		return url.URL{}, "", E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	if !strings.HasSuffix(requestURL.Path, "/") {
		requestURL.Path += "/"
	}

	var requestHost string
	switch {
	case host != "":
		requestHost = host
	case tlsConfig != nil && tlsConfig.ServerName() != "":
		requestHost = tlsConfig.ServerName()
	default:
		requestHost = serverAddr.String()
	}
	return requestURL, requestHost, nil
}

// newHTTPClient builds an HTTP/2 client over the given dialer.
//
// xhttp needs full-duplex HTTP: over HTTP/1.1 the server cannot answer before the request body
// ends, so h2 (over TLS) or h2c (prior knowledge, no TLS) is required.
func newHTTPClient(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config) (*http.Client, error) {
	if tlsConfig == nil {
		return &http.Client{Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(dialContext context.Context, network string, addr string, cfg *stdtls.Config) (net.Conn, error) {
				return dialer.DialContext(dialContext, N.NetworkTCP, serverAddr)
			},
		}}, nil
	}
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, E.Cause(err, "build tls config")
	}
	if len(stdConfig.NextProtos) == 0 {
		stdConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	return &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   stdConfig,
		DialContext: func(dialContext context.Context, network string, addr string) (net.Conn, error) {
			return dialer.DialContext(dialContext, N.NetworkTCP, serverAddr)
		},
		IdleConnTimeout: 90 * time.Second,
	}}, nil
}

// withSession appends the session id to the path, matching Xray's appendToPath().
func withSession(base url.URL, sessionID string) url.URL {
	result := base
	if strings.HasSuffix(result.Path, "/") {
		result.Path += sessionID
	} else {
		result.Path += "/" + sessionID
	}
	return result
}

const sessionIDTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func generateSessionID() string {
	id := make([]byte, 16)
	for i := range id {
		id[i] = sessionIDTable[rand.IntN(len(sessionIDTable))]
	}
	return string(id)
}

func (c *Client) Close() error {
	closeIdle(c.uploadClient)
	if c.downloadClient != c.uploadClient {
		closeIdle(c.downloadClient)
	}
	return nil
}

func closeIdle(client *http.Client) {
	if client == nil {
		return
	}
	switch transport := client.Transport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
	case *http2.Transport:
		transport.CloseIdleConnections()
	}
}

// Conn adapts an in-flight HTTP request/response pair into a net.Conn: writes go into the request
// body, reads come from the response body.
type Conn struct {
	reader     *waitReader
	writer     *io.PipeWriter
	pipeReader *io.PipeReader
	remoteAddr net.Addr
	localAddr  net.Addr

	closeOnce sync.Once
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.pipeReader.CloseWithError(io.EOF)
		c.writer.CloseWithError(io.EOF)
		c.reader.close()
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return M.Socksaddr{}
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return M.Socksaddr{}
}

func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

// waitReader blocks until the HTTP response headers arrive, then reads the response body.
type waitReader struct {
	wait chan struct{}
	body io.ReadCloser
	err  error
	once sync.Once
}

func (r *waitReader) set(body io.ReadCloser) {
	r.once.Do(func() {
		r.body = body
		close(r.wait)
	})
}

func (r *waitReader) closeWith(err error) {
	r.once.Do(func() {
		r.err = err
		close(r.wait)
	})
}

func (r *waitReader) close() {
	r.once.Do(func() { close(r.wait) })
	if r.body != nil {
		r.body.Close()
	}
}

func (r *waitReader) Read(p []byte) (int, error) {
	<-r.wait
	if r.err != nil {
		return 0, r.err
	}
	if r.body == nil {
		return 0, io.EOF
	}
	return r.body.Read(p)
}
