/** A small Go service: net/http, gin, echo and chi routes, main, init and tests. */
export const GO_APP: Record<string, string> = {
  'cmd/server/main.go': `package main

import (
	"net/http"

	"example.com/app/internal/core"
	"example.com/app/internal/web"
)

func main() {
	svc := core.NewService(core.NewMemStore())
	web.Register(http.DefaultServeMux, svc)
	_ = http.ListenAndServe(":8080", nil)
}
`,
  'internal/core/store.go': `package core

type Store interface {
	Load(key string) (string, error)
}

type MemStore struct{ data map[string]string }

func NewMemStore() *MemStore { return &MemStore{data: map[string]string{}} }

func (m *MemStore) Load(key string) (string, error) { return m.data[key], nil }

func (m *MemStore) Legacy() int { return 1 }
`,
  'internal/core/service.go': `package core

import "strings"

var registry = map[string]int{}

func init() { registry["x"] = 1 }

type Service struct{ store Store }

func NewService(s Store) *Service { return &Service{store: s} }

func (s *Service) Find(key string) (string, error) { return s.store.Load(strings.ToLower(key)) }

func (s *Service) Unused() int { return 0 }

func (s *Service) OnlyTested() int { return s.helper() }

func (s *Service) helper() int { return 2 }

func Format(v string) string { return v }
`,
  'internal/core/service_test.go': `package core

import "testing"

func TestOnlyTested(t *testing.T) {
	s := NewService(NewMemStore())
	if s.OnlyTested() != 2 {
		t.Fatal("bad")
	}
}

func BenchmarkFind(b *testing.B) {}
`,
  'internal/web/routes.go': `package web

import (
	"net/http"

	"example.com/app/internal/core"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/labstack/echo/v4"
)

type Handler struct{ svc *core.Service }

func Register(mux *http.ServeMux, svc *core.Service) {
	h := &Handler{svc: svc}
	mux.HandleFunc("GET /users/{id}", h.getUser)
	mux.Handle("/health", http.HandlerFunc(health))
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	v, _ := h.svc.Find(r.PathValue("id"))
	_, _ = w.Write([]byte(core.Format(v)))
}

func health(w http.ResponseWriter, r *http.Request) {}

func Gin(r *gin.Engine) {
	api := r.Group("/api")
	api.GET("/items/:id", listItems)
	api.POST("/items", func(c *gin.Context) { createItem(c) })
}

func listItems(c *gin.Context) {}

func createItem(c *gin.Context) {}

func Echo(e *echo.Echo) {
	g := e.Group("/v2")
	g.GET("/ping", ping)
}

func ping(c echo.Context) error { return nil }

func Chi(r chi.Router) {
	r.Route("/orders", func(r chi.Router) {
		r.Get("/{id}", getOrder)
	})
}

func getOrder(w http.ResponseWriter, r *http.Request) {}

func orphan() {}
`,
};
