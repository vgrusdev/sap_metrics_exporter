package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	//"math/rand"
	"net/http"
	"runtime/debug"
	"time"

	//"github.com/vgrusdev/sap_metrics_exporter/metrics"
	"github.com/vgrusdev/sap_metrics_exporter/utils"
)

// RequestLogger logs HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	logger := utils.NewLogger("http")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response wrapper to capture status code
		rw := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
		}

		// Log request
		logger.Info("HTTP request started",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)

		// Process request
		next.ServeHTTP(rw, r)

		// Log response
		duration := time.Since(start)
		logger.Info("HTTP request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration", duration,
			"size", rw.size,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code and size
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// RecoveryMiddleware recovers from panics
func recoveryMiddleware(next http.Handler) http.Handler {
	logger := utils.NewLogger("recovery")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic
				logger.Error("PANIC recovered",
					"error", err,
					"stack", string(debug.Stack()),
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
				)

				// Return error response
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error":"Internal Server Error","timestamp":"%s"}`,
					time.Now().Format(time.RFC3339))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware adds CORS headers
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware adds basic authentication
func AuthMiddleware(username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"Unauthorized","timestamp":"%s"}`,
				time.Now().Format(time.RFC3339))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware adds rate limiting
func RateLimitMiddleware(requestsPerSecond int, next http.Handler) http.Handler {
	// Simple token bucket implementation
	tokens := make(chan struct{}, requestsPerSecond)
	ticker := time.NewTicker(time.Second / time.Duration(requestsPerSecond))

	// Fill the bucket
	go func() {
		for range ticker.C {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-tokens:
			next.ServeHTTP(w, r)
		default:
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"error":"Too Many Requests","timestamp":"%s"}`,
				time.Now().Format(time.RFC3339))
		}
	})
}

// TimeoutMiddleware adds request timeout
func TimeoutMiddleware(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create context with timeout
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		// Create channel to detect completion
		done := make(chan bool, 1)
		panicChan := make(chan interface{}, 1)

		// Wrap the handler to catch panics
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if p := recover(); p != nil {
					panicChan <- p
				}
			}()
			next.ServeHTTP(w, r)
			done <- true
		})

		// Create request with timeout context
		req := r.WithContext(ctx)

		// Execute handler in goroutine
		go handler.ServeHTTP(w, req)

		// Wait for completion or timeout
		select {
		case <-done:
			// Request completed normally
			return
		case p := <-panicChan:
			// Panic occurred
			panic(p)
		case <-ctx.Done():
			// Timeout occurred
			w.WriteHeader(http.StatusGatewayTimeout)
			fmt.Fprintf(w, `{"error":"Request Timeout","timestamp":"%s"}`,
				time.Now().Format(time.RFC3339))
		}
	})
}

/*
// MetricsMiddleware adds Prometheus metrics for HTTP requests
func MetricsMiddleware(registry *metrics.Registry, next http.Handler) http.Handler {
	// This would require adding HTTP metrics to the metrics registry
	// For now, it's a placeholder for metrics collection

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response wrapper
		rw := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
		}

		// Process request
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(start).Seconds()

		// Here you would update Prometheus metrics
		// Example:
		// registry.HTTPRequestsTotal.WithLabelValues(
		//     r.Method,
		//     r.URL.Path,
		//     fmt.Sprintf("%d", rw.status),
		// ).Inc()
		//
		// registry.HTTPRequestDuration.WithLabelValues(
		//     r.URL.Path,
		// ).Observe(duration)
	})
}
*/

// CompressionMiddleware adds gzip compression
func CompressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client accepts gzip
		acceptsGzip := false
		for _, encoding := range r.Header.Values("Accept-Encoding") {
			if encoding == "gzip" {
				acceptsGzip = true
				break
			}
		}
		if !acceptsGzip {
			next.ServeHTTP(w, r)
			return
		}
		// Create gzip writer
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()

		gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzr, r)
	})
}

// gzipResponseWriter wraps http.ResponseWriter with gzip.Writer
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// SecurityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware adds request ID for tracing
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate or get request ID
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Set request ID in header
		w.Header().Set("X-Request-ID", requestID)

		// Add to request context
		ctx := context.WithValue(r.Context(), "requestID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateRequestID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString(8))
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	max := big.NewInt(int64(len(charset)))
	b := make([]byte, length)
	for i := range b {
		index, _ := rand.Int(rand.Reader, max)
		b[i] = charset[index.Int64()]
	}
	return string(b)
}

// ChainMiddleware chains multiple middlewares together
func ChainMiddleware(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
