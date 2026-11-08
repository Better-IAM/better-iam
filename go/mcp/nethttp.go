package mcp

// The net/http form of the gate: Handler puts the gate in front of an http.Handler-style MCP server. The server's
// answer streams through the gate (event streams are filtered as they arrive).

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// HandlerFunc is an MCP server handler that also receives the authenticated caller.
type HandlerFunc func(w http.ResponseWriter, r *http.Request, caller *Caller)

type callerKey struct{}

// CallerFrom is the authenticated caller of a request the gate passed on (nil when none).
func CallerFrom(r *http.Request) *Caller {
	caller, _ := r.Context().Value(callerKey{}).(*Caller)
	return caller
}

// Handler is the gate in front of next. The caller is passed to next and is also on the request (CallerFrom).
func (g *Gate) Handler(next HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := g.Handle(r, func(forward *http.Request, caller *Caller) (*http.Response, error) {
			forward = forward.WithContext(context.WithValue(forward.Context(), callerKey{}, caller))
			return serve(forward, func(w http.ResponseWriter, r *http.Request) { next(w, r, caller) }), nil
		})
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeResponse(w, response)
	})
}

// serve runs an http.Handler-style handler and answers its response as soon as it starts, its body streaming
// through a pipe.
func serve(r *http.Request, handler func(w http.ResponseWriter, r *http.Request)) *http.Response {
	reader, writer := io.Pipe()
	recorder := &pipeWriter{header: http.Header{}, body: writer, started: make(chan struct{})}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if !recorder.headerSent() {
					recorder.header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
					recorder.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(writer, "Internal Server Error\n")
				}
				_ = writer.CloseWithError(io.ErrUnexpectedEOF)
				return
			}
			recorder.WriteHeader(http.StatusOK)
			_ = writer.Close()
		}()
		handler(recorder, r)
	}()
	<-recorder.started
	response := newResponse(recorder.status, recorder.sent, nil)
	response.Body = reader
	response.ContentLength = -1
	return response
}

// pipeWriter is a ResponseWriter whose body is the write end of a pipe.
type pipeWriter struct {
	mu      sync.Mutex
	header  http.Header
	sent    http.Header
	status  int
	body    *io.PipeWriter
	started chan struct{}
}

func (p *pipeWriter) Header() http.Header { return p.header }

func (p *pipeWriter) headerSent() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent != nil
}

func (p *pipeWriter) WriteHeader(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sent != nil {
		return
	}
	p.status = status
	p.sent = p.header.Clone()
	close(p.started)
}

func (p *pipeWriter) Write(data []byte) (int, error) {
	p.WriteHeader(http.StatusOK)
	return p.body.Write(data)
}

// Flush is a no-op: every write already reaches the reader.
func (p *pipeWriter) Flush() {}

// writeResponse writes a gate answer, flushing as the body arrives (event streams).
func writeResponse(w http.ResponseWriter, response *http.Response) {
	header := w.Header()
	for key, values := range response.Header {
		header[key] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	if response.Body == nil {
		return
	}
	defer func() { _ = response.Body.Close() }()
	flusher, _ := w.(http.Flusher)
	buffer := make([]byte, 32*1024)
	for {
		count, err := response.Body.Read(buffer)
		if count > 0 {
			if _, writeErr := w.Write(buffer[:count]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
