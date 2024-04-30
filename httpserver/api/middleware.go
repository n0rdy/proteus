package api

import (
	"bytes"
	"fmt"
	"github.com/google/uuid"
	"github.com/n0rdy/proteus/httpserver/logger"
	"io"
	"net/http"
)

func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// reassign the body because it has been read:
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		requestId := r.Header.Get("X-Request-Id")
		if requestId == "" {
			requestId = uuid.New().String()
		}

		lrw := &logResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		logger.Debug("[" + requestId + "] Request received: " + r.Method + " " + r.URL.Path + "\n" +
			">>>>>> Body: " + string(body) + "\n" +
			">>>>>> Headers: " + fmt.Sprintf("%v", r.Header) + "\n" +
			">>>>>> Query Params: " + fmt.Sprintf("%v", r.URL.Query()) + "\n" +
			">>>>>> Cookies: " + fmt.Sprintf("%v", r.Cookies()),
		)

		next.ServeHTTP(lrw, r)

		logger.Debug("[" + requestId + "] Response sent: " + fmt.Sprintf("%d\n", lrw.statusCode) +
			"<<<<<< Body: " + lrw.body.String() + "\n" +
			"<<<<<< Headers: " + fmt.Sprintf("%v", lrw.Header()),
		)
	})
}

// Custom response writer to capture response status and body
type logResponseWriter struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (lrw *logResponseWriter) Write(b []byte) (int, error) {
	lrw.body.Write(b)
	return lrw.ResponseWriter.Write(b)
}

func (lrw *logResponseWriter) WriteHeader(statusCode int) {
	lrw.statusCode = statusCode
	lrw.ResponseWriter.WriteHeader(statusCode)
}

func (lrw *logResponseWriter) Header() http.Header {
	return lrw.ResponseWriter.Header()
}
