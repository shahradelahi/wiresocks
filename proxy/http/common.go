package http

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

const (
	CRLF = "\r\n"
)

// Authenticator is an interface for authenticating users.
type Authenticator interface {
	Authenticate(req *http.Request) bool
}

// BasicAuthenticator is an Authenticator that uses basic authentication.
type BasicAuthenticator struct {
	Credentials statute.CredentialStore
}

// Authenticate authenticates the user using basic authentication.
func (a *BasicAuthenticator) Authenticate(req *http.Request) bool {
	if a.Credentials == nil {
		return true
	}

	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	encoded := authHeader[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}

	return a.Credentials.Valid(parts[0], parts[1])
}

// copyBuffer is a helper function to copy data between two net.Conn objects.
// func copyBuffer(dst, src net.Conn, buf []byte) (int64, error) {
// 	return io.CopyBuffer(dst, src, buf)
// }

type responseWriter struct {
	conn    net.Conn
	headers http.Header
	status  int
	written bool
}

func NewHTTPResponseWriter(conn net.Conn) http.ResponseWriter {
	return &responseWriter{
		conn:    conn,
		headers: http.Header{},
		status:  http.StatusOK,
	}
}

func (rw *responseWriter) Header() http.Header {
	return rw.headers
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.written {
		return
	}
	rw.status = statusCode
	rw.written = true

	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = fmt.Sprintf("status code %d", statusCode)
	}

	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "HTTP/1.1 %d %s%s", statusCode, statusText, CRLF)
	_ = rw.headers.Write(&buf)
	_, _ = buf.WriteString(CRLF)
	_, _ = rw.conn.Write(buf.Bytes())
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.conn.Write(data)
}
