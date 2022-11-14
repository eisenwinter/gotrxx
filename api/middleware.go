package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"golang.org/x/text/language"
)

func languageMiddleware(defaultLang string, registry *i18n.TranslationRegistry) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			lang := defaultLang
			if c, err := r.Cookie(string(i18n.ContextLangKey)); err == nil {
				if registry.ContainsLanguage(c.Value) {
					lang = c.Value
				}
			} else {
				accept := r.Header.Get("Accept-Language")
				tag, _ := language.MatchStrings(registry.Matcher(), lang, accept)
				l, _ := tag.Base()
				lang = l.String()
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), i18n.ContextLangKey, lang)))
		}
		return http.HandlerFunc(fn)
	}
}

// Logger is a middleware that logs the start and end of each request, along
// with some useful data about what was requested, what the response status was,
// and how long it took to return.
// bluntly stolen from https://github.com/treastech/logger/blob/master/logger.go

func loggerMiddleware(l *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()
			defer func() {
				l.Info(fmt.Sprintf("[%s] %s", r.Method, r.URL.Path),
					zap.String("proto", r.Proto),
					zap.String("path", r.URL.Path),
					zap.Duration("latency", time.Since(t1)),
					zap.Int("status", ww.Status()),
					zap.Int("size", ww.BytesWritten()),
					zap.String("requestID", middleware.GetReqID(r.Context())))
			}()

			next.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}
}
