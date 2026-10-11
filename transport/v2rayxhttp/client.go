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
	dialer     N.Dialer
	serverAddr M.Socksaddr
	requestURL url.URL
	host       string
	headers    http.Header
	method     string
	httpClient *http.Client
	noGRPC     bool

	paddingFrom int
	paddingTo   int
	paddingKey  string
	paddingHdr  string
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (*Client, error) {
	// xhttp's stream-one mode needs a full-duplex HTTP connection: the uplink streams in the
	// request body while the downlink streams out of the response body. Over HTTP/1.1 the server
	// cannot answer before the request body ends, so this only works over HTTP/2 — including
	// h2c (prior-knowledge) when there is no TLS.
	var roundTripper http.RoundTripper
	if tlsConfig == nil {
		roundTripper = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(dialContext context.Context, network string, addr string, cfg *stdtls.Config) (net.Conn, error) {
				return dialer.DialContext(dialContext, N.NetworkTCP, serverAddr)
			},
		}
	} else {
		stdConfig, err := tlsConfig.STDConfig()
		if err != nil {
			return nil, E.Cause(err, "build tls config")
		}
		if len(stdConfig.NextProtos) == 0 {
			stdConfig.NextProtos = []string{"h2", "http/1.1"}
		}
		roundTripper = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   stdConfig,
			DialContext: func(dialContext context.Context, network string, addr string) (net.Conn, error) {
				return dialer.DialContext(dialContext, N.NetworkTCP, serverAddr)
			},
			IdleConnTimeout: 90 * time.Second,
		}
	}

	var host string
	if options.Host != "" {
		host = options.Host
	} else if tlsConfig != nil && tlsConfig.ServerName() != "" {
		host = tlsConfig.ServerName()
	} else {
		host = serverAddr.String()
	}

	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = serverAddr.String()
	err := sHTTP.URLSetPath(&requestURL, options.Path)
	if err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	// Xray's default session/seq placement is `path`, so GetNormalizedPath() keeps a trailing
	// slash and the server matches with HasPrefix(path).
	if !strings.HasSuffix(requestURL.Path, "/") {
		requestURL.Path += "/"
	}

	headers := make(http.Header)
	for key, value := range options.Headers {
		headers[key] = value
	}

	method := options.UplinkHTTPMethod
	if method == "" {
		method = http.MethodPost
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
		dialer:      dialer,
		serverAddr:  serverAddr,
		requestURL:  requestURL,
		host:        host,
		headers:     headers,
		method:      method,
		httpClient:  &http.Client{Transport: roundTripper},
		noGRPC:      options.NoGRPCHeader,
		paddingFrom: paddingFrom,
		paddingTo:   paddingTo,
		paddingKey:  paddingKey,
		paddingHdr:  paddingHeader,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()

	request := (&http.Request{
		Method: c.method,
		URL:    &c.requestURL,
		Host:   c.host,
		Header: c.headers.Clone(),
		Body:   pipeReader,
	}).WithContext(context.WithoutCancel(ctx))

	if !c.noGRPC {
		request.Header.Set("Content-Type", "application/grpc")
	}
	c.applyXPadding(request)

	gotConn := make(chan struct{})
	var remoteAddr, localAddr net.Addr
	var gotConnOnce sync.Once
	traceCtx := httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			remoteAddr = info.Conn.RemoteAddr()
			localAddr = info.Conn.LocalAddr()
			gotConnOnce.Do(func() { close(gotConn) })
		},
	})
	request = request.WithContext(traceCtx)

	conn := &Conn{
		reader:     &waitReader{wait: make(chan struct{})},
		writer:     pipeWriter,
		pipeReader: pipeReader,
	}
	go func() {
		response, err := c.httpClient.Do(request)
		if err != nil {
			conn.reader.closeWith(err)
			pipeReader.CloseWithError(err)
			gotConnOnce.Do(func() { close(gotConn) })
			return
		}
		if response.StatusCode != http.StatusOK {
			conn.reader.closeWith(E.New("unexpected status: ", response.Status))
			response.Body.Close()
			pipeReader.Close()
			return
		}
		conn.reader.set(response.Body)
	}()

	select {
	case <-gotConn:
	case <-ctx.Done():
		pipeReader.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
	conn.remoteAddr = remoteAddr
	conn.localAddr = localAddr
	return conn, nil
}

func (c *Client) applyXPadding(request *http.Request) {
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
	// Xray's default placement is "query in header": the request URL with a `x_padding` query
	// is written into the Referer header.
	paddingURL := c.requestURL
	query := paddingURL.Query()
	query.Set(c.paddingKey, strings.Repeat("X", length))
	paddingURL.RawQuery = query.Encode()
	request.Header.Set(c.paddingHdr, paddingURL.String())
}

func (c *Client) Close() error {
	switch transport := c.httpClient.Transport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
	case *http2.Transport:
		transport.CloseIdleConnections()
	}
	return nil
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
