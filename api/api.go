package api

import (
	"net/http"
	"time"

	"github.com/google/safehtml/template"

	"github.com/eisenwinter/gotrxx/api/app/connect"
	"github.com/eisenwinter/gotrxx/api/app/management"
	"github.com/eisenwinter/gotrxx/api/app/meta"
	"github.com/eisenwinter/gotrxx/api/app/netlify"
	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"

	ar "github.com/eisenwinter/gotrxx/api/app/account"
)

var tokenAuth *jwtauth.JWTAuth

func compose(logger logging.Logger,
	cfg *config.Configuration,
	issuer *tokens.TokenIssuer,
	signInService *user.SigninService,
	userService *user.Service,
	rotator *tokens.TokenRotator,
	authService *authorization.Service,
	appService *application.Service,
	registry *i18n.TranslationRegistry,
	fileSystems *config.FileSystems,
	manageUserService *manage.UserService,
	manageAppService *manage.ApplicationService,
	manageAuthService *manage.AuthorizationService,
	manageRoleService *manage.RoleService,
	manageInviteService *manage.InviteService,
	verifier *tokens.TokenVerifier) (*chi.Mux, error) {

	// use same settings as issuer (duh)
	tokenAuth = jwtauth.New(issuer.Alg(), issuer.PrivateKey(), issuer.PublicKey())

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	r.Use(loggerMiddleware(logger))

	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(50 * time.Second))
	if len(registry.Languages()) > 1 {
		r.Use(languageMiddleware(cfg.Behaviour.DefaultLocale, registry))
	}
	r.Use(jwtauth.Verifier(tokenAuth))

	if cfg.DebugMode() {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("running in debug mode - no auto redirects to site"))
		})
	} else {
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, cfg.Behaviour.Site, http.StatusFound)
		})
	}

	connectRessource := connect.NewConnnectRessource(
		logger.WithGroup("connect_ressource"),
		tokenAuth,
		issuer,
		rotator,
		signInService,
		authService,
		appService,
		verifier,
	)
	netlifyRessource := netlify.NewNetlifyRessource(
		logger.WithGroup("netlify_ressource"),
		tokenAuth,
		connectRessource,
		rotator,
	)
	accountRessource := ar.NewAccountRessource(
		logger.WithGroup("account_ressource"),
		signInService,
		cfg.Behaviour,
		userService,
		authService,
		issuer,
		registry,
		rotator,
		cfg.Server,
		fileSystems,
		verifier,
	)
	metaRessource := meta.NewMetaRessource(logger.WithGroup("meta_ressource"), cfg.Behaviour, issuer)

	if cfg.ManageEndpoint.Enable {
		manageRessource := management.NewManagementRessource(
			logger.WithGroup("management_ressource"),
			*cfg,
			tokenAuth,
			manageUserService,
			manageAppService,
			manageAuthService,
			manageRoleService,
			manageInviteService,
		)
		r.Mount("/manage", manageRessource.Router())
	}

	r.Mount("/connect", connectRessource.Router())

	r.Mount("/account", accountRessource.Router())

	r.Mount("/.netlify", netlifyRessource.Router())

	r.Mount("/.well-known", metaRessource.Router())

	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		favicon, err := fileSystems.StaticFolder.Open("favicon.ico")
		if err == nil {
			defer favicon.Close()
			s, err := favicon.Stat()
			if err == nil {
				buffer := make([]byte, s.Size())
				_, err = favicon.Read(buffer)
				if err != nil {
					logger.Warn("Unable to load favicon", "err", err)
				}
				_, err = w.Write(buffer)
				if err != nil {
					logger.Warn("Unable to write favicon", "err", err)
				}
				return
			}

		}
		logger.Warn("no favicon found", "err", err)
	})

	r.Get("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		var robotsTemplate, err = template.New("robots.txt").Parse(
			`User-agent: *
Disallow: /
		`)
		if err != nil {
			return
		}
		_ = robotsTemplate.Execute(w, nil)
	})
	return r, nil
}
