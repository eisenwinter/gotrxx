package management

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/sanitize"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ManagementRessource habours the headless admin endpoints
type ManagementRessource struct {
	log           *zap.Logger
	cfg           config.Configuration
	userService   *manage.UserService
	authService   *manage.AuthorizationService
	appService    *manage.ApplicationService
	roleService   *manage.RoleService
	inviteService *manage.InviteService
}

func (m *ManagementRessource) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   m.cfg.ManageEndpoint.CORS.AllowedOrigins,
		AllowedMethods:   m.cfg.ManageEndpoint.CORS.AllowedMethods,
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: m.cfg.ManageEndpoint.CORS.AllowCredentials,
		MaxAge:           300,
	}))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		m.log.Debug(
			"Could not found",
			zap.String("method", r.Method),
			sanitize.UserInputString("path", r.URL.Path),
		)
		w.WriteHeader(404)
	})

	r.Get("/.ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})

	r.Group(func(gr chi.Router) {
		gr.Use(jwtauth.Authenticator)
		gr.Use(adminOnlyMiddleWare(!m.cfg.JWT.NoRolesClaim, m.userService))
		gr.Route("/applications", func(r chi.Router) {
			r.With(pageinate).Get("/", m.listApplications)
			r.Get("/by-client-id", m.appByClientId)
			r.Post("/create", m.createApplication)
			r.Put("/retire", m.retireApplication)
			r.Post("/with-authorization-for", m.applicationsWithActiveAuthorizationsByUserID)
			r.Delete("/purge", m.purgeRetiredApllications)

			r.Route("/properties", func(pr chi.Router) {

				pr.Route("/flow", func(r chi.Router) {
					r.Put("/add", m.addFlowToApplication)
					r.Put("/remove", m.removeFlowFromApplication)
				})

				pr.Route("/logout-uri", func(r chi.Router) {
					r.Put("/add", m.addLogoutUriToApplication)
					r.Put("/remove", m.removeLogoutUriFromApplication)
				})

				pr.Route("/redirect-uri", func(r chi.Router) {
					r.Put("/add", m.addRedirectUriToApplication)
					r.Put("/remove", m.removeRedirectURIFromApplication)
				})

				pr.Route("/pkce", func(r chi.Router) {
					r.Put("/enable", m.enablePKCEForApplication)
					r.Put("/disable", m.disablePKCEForApplication)
				})

			})

			r.Put("/secret/set", m.updateSecretOfApplication)
		})
		gr.Route("/authorizations", func(r chi.Router) {
			r.With(pageinate).Get("/", m.listAuthorizations)
			r.Post("/grant", m.grantAuthorization)
			r.Post("/revoke", m.revokeAuthorization)
			r.Post("/active-by-user", m.activeAuthorizationsByUserID)
		})
		gr.Route("/users", func(r chi.Router) {
			r.With(pageinate).Get("/", m.listUsers)
			r.Get("/by-id", m.userByID)
			r.Route("/role", func(ri chi.Router) {
				ri.Post("/add", m.addUserToRole)
				ri.Put("/remove", m.removeUserFromRole)
			})
			r.Put("/ban", m.banUser)
			r.Put("/confirm", m.confirmUser)
			r.Put("/unban", m.unbanUser)
			r.Put("/unlock", m.unlockUser)
		})
		gr.Route("/roles", func(r chi.Router) {
			r.With(pageinate).Get("/", m.listRoles)
		})
		gr.Route("/invites", func(r chi.Router) {
			r.With(pageinate).Get("/", m.listInvites)
			r.Post("/create", m.createInvite)
		})
	})
	return r
}

type roleChecker interface {
	VerifyUserInRole(ctx context.Context, userID uuid.UUID, role string) error
}

func NewManagementRessource(logger *zap.Logger,
	cfg config.Configuration,
	userService *manage.UserService,
	appService *manage.ApplicationService,
	authService *manage.AuthorizationService,
	roleService *manage.RoleService,
	inviteService *manage.InviteService) *ManagementRessource {
	return &ManagementRessource{
		log:           logger,
		cfg:           cfg,
		userService:   userService,
		authService:   authService,
		appService:    appService,
		roleService:   roleService,
		inviteService: inviteService,
	}
}

type accountKey string

var pageSizeKey accountKey = "page_size"
var pageKey accountKey = "page"
var queryKey accountKey = "query"
var sortKey accountKey = "sort"

func pageinate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p := r.URL.Query().Get("page")

		intOrDefault := func(in string, def int) int {
			if in == "" {
				return def
			}
			i, err := strconv.Atoi(in)
			if err != nil {
				return def
			}
			return i
		}
		ctx = context.WithValue(ctx, pageKey, intOrDefault(p, 1))
		s := r.URL.Query().Get("page_size")
		ctx = context.WithValue(ctx, pageSizeKey, intOrDefault(s, 12))

		q := r.URL.Query().Get("query")
		ctx = context.WithValue(ctx, queryKey, q)

		sort := r.URL.Query().Get("sort")
		ctx = context.WithValue(ctx, sortKey, sort)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func adminOnlyMiddleWare(rolesInToken bool, rc roleChecker) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			token, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			if rolesInToken {
				if _, ok := claims[tokens.ClaimRoles]; !ok {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				if claims[tokens.ClaimRoles] == nil {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				arr := claims[tokens.ClaimRoles].([]interface{})
				if len(arr) == 0 {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				found := false
				for _, v := range arr {
					r := v.(string)
					if strings.ToLower(r) == "admin" {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
			} else {
				tokenID := token.Subject()
				id, err := uuid.Parse(tokenID)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				err = rc.VerifyUserInRole(r.Context(), id, "admin")
				if err != nil {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}

			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
