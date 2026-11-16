package api

import (
	"net/http"
	"sort"
	"strings"
)

// Router is a minimal exact-path router. It exists instead of
// http.ServeMux so that 404 and 405 responses are structured problems and
// so that the access log records the registered route, never the raw path.
type Router struct {
	routes map[string]map[string]http.Handler
}

// NewRouter returns an empty router.
func NewRouter() *Router {
	return &Router{routes: make(map[string]map[string]http.Handler)}
}

// Handle registers handler for an exact method and path. It panics on
// duplicate registration, which is a programming error.
func (rt *Router) Handle(method, path string, handler http.Handler) {
	methods, ok := rt.routes[path]
	if !ok {
		methods = make(map[string]http.Handler)
		rt.routes[path] = methods
	}
	if _, dup := methods[method]; dup {
		panic("api: duplicate route " + method + " " + path)
	}
	methods[method] = handler
}

// HandleFunc is Handle for a function.
func (rt *Router) HandleFunc(method, path string, handler http.HandlerFunc) {
	rt.Handle(method, path, handler)
}

// ServeHTTP dispatches on the exact path and method.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	methods, ok := rt.routes[r.URL.Path]
	if !ok {
		setRoute(r.Context(), "unmatched")
		WriteProblem(w, r, http.StatusNotFound, CodeNotFound, "no such endpoint")
		return
	}
	setRoute(r.Context(), r.URL.Path)
	handler, ok := methods[r.Method]
	if !ok && r.Method == http.MethodHead {
		handler, ok = methods[http.MethodGet]
	}
	if !ok {
		allowed := make([]string, 0, len(methods))
		for method := range methods {
			allowed = append(allowed, method)
		}
		sort.Strings(allowed)
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		WriteProblem(w, r, http.StatusMethodNotAllowed, CodeMethodNotAllowed, "method not allowed for this endpoint")
		return
	}
	handler.ServeHTTP(w, r)
}
