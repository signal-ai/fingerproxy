// Package `reverseproxy` forwards the requests to backends. It gets
// additional request headers from `header_injectors`, and adds to the
// forwarding request to downstream.
package reverseproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type HTTPHandler struct {
	// required, internal reverse proxy that forwards the requests
	reverseProxy *httputil.ReverseProxy

	// the URL that requests will be forwarding to if the `X-Forwarded-Host` is not set
	To *url.URL

	// optional, preserve the host in outbound requests
	PreserveHost bool

	// optional, but in fact required, injecting fingerprint headers to outbound requests
	HeaderInjectors []HeaderInjector

	// optional, if IsProbeRequest returns true, handler will respond with
	// a HTTP 200 OK instead of forwarding requests, useful for kubernetes
	// liveness/readiness probes. defaults to nil, which disables this behavior
	IsProbeRequest func(*http.Request) bool
}

const (
	ProbeStatusCode = http.StatusOK
	ProbeResponse   = "OK"
)

// NewHTTPHandler creates an HTTP handler, changes `reverseProxy.Rewrite` to support request
// header injection, then assigns `reverseProxy` to the handler which proxies requests to backend
func NewHTTPHandler(to *url.URL, reverseProxy *httputil.ReverseProxy, headerInjectors []HeaderInjector) *HTTPHandler {
	f := &HTTPHandler{
		To:              to,
		reverseProxy:    reverseProxy,
		HeaderInjectors: headerInjectors,
	}

	f.reverseProxy.Rewrite = f.rewriteFunc
	f.reverseProxy.ErrorHandler = f.errorHandler
	return f
}

type contextKey string

const (
    proxyErrorKey contextKey = "proxyError"
)
func (f *HTTPHandler) rewriteFunc(r *httputil.ProxyRequest) {
	if destination := r.In.Header.Get("X-Destination"); destination != ""  {
		targetURL, err := url.Parse(destination)
        if err != nil {
			ctx := context.WithValue(r.In.Context(), proxyErrorKey, errors.New("Invalid X-Destination"))
			r.In = r.In.WithContext(ctx)

            // Set to a non-routable address
            targetURL, _ = url.Parse("http://127.0.0.1:1")
		} else {
			f.logf("using target url %v", targetURL.String())
		}
		r.SetURL(targetURL)
		r.Out.Header.Del("X-Destination")
	} else if f.To != nil {
		r.SetURL(f.To)
	}  else {
		ctx := context.WithValue(r.In.Context(), proxyErrorKey, errors.New("No URL provided"))
		r.In = r.In.WithContext(ctx)
	}

	r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
	r.SetXForwarded()

	if f.PreserveHost {
		r.Out.Host = r.In.Host
	}

	for _, hj := range f.HeaderInjectors {
		k := hj.GetHeaderName()
		if v, err := hj.GetHeaderValue(r.In); err != nil {
			f.logf("get header %s value for %s failed: %s", k, r.In.RemoteAddr, err)
		} else if v != "" { // skip empty header values
			r.Out.Header.Set(k, v)
		}
	}
}

func (f *HTTPHandler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if proxyErr, ok := r.Context().Value(proxyErrorKey).(error); ok {
		http.Error(w, fmt.Sprintf("Proxy error: %s", proxyErr), http.StatusBadGateway)
		return
	}

	// Handle standard transport errors
	http.Error(w, fmt.Sprintf("Proxy error: %s", err), http.StatusBadGateway)
}

func (f *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if f.IsProbeRequest != nil && f.IsProbeRequest(req) {
		w.WriteHeader(ProbeStatusCode)
		w.Write([]byte(ProbeResponse))
		return
	}
	f.reverseProxy.ServeHTTP(w, req)
}

func IsKubernetesProbeRequest(r *http.Request) bool {
	// https://github.com/kubernetes/kubernetes/blob/656cb1028ea5af837e69b5c9c614b008d747ab63/pkg/probe/http/request.go#L91
	return strings.HasPrefix(r.UserAgent(), "kube-probe/")
}

func (f *HTTPHandler) logf(format string, args ...any) {
	if f.reverseProxy.ErrorLog != nil {
		f.reverseProxy.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
