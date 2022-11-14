package netlify

import (
	"net/http"

	"github.com/eisenwinter/gotrxx/api/app/connect"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"

	"go.uber.org/zap"
)

type NetlifyRessource struct {
	logger *zap.Logger
	//nelitfy ressource just wraps the underlying connect ressource
	uc *connect.ConnnectRessource
}

func (n *NetlifyRessource) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	//this is the miniaml subset required for git-gateway and netlifycms
	r.Post("/token", n.token)
	r.Group(func(gr chi.Router) {
		gr.Use(jwtauth.Authenticator)
		gr.Get("/user", n.user)
	})
	r.Get("/settings", n.settings)

	return r
}

type settingsResponse struct {
	External struct {
		Bitbucket bool `json:"bitbucket"`
		Github    bool `json:"github"`
		Gitlab    bool `json:"gitlab"`
		Google    bool `json:"google"`
		Facebook  bool `json:"facebook"`
		Email     bool `json:"email"`
		Saml      bool `json:"saml"`
	} `json:"external"`
	ExternalLabels struct {
	} `json:"external_labels"`
	DisableSignup bool `json:"disable_signup"`
	Autoconfirm   bool `json:"autoconfirm"`
}

func newSettingsResponse() *settingsResponse {
	//so we gonna lie a bluntly so we can use netflifycms and gitgateway (:
	res := &settingsResponse{
		Autoconfirm:    false,
		DisableSignup:  true,
		ExternalLabels: struct{}{},
		External: struct {
			Bitbucket bool "json:\"bitbucket\""
			Github    bool "json:\"github\""
			Gitlab    bool "json:\"gitlab\""
			Google    bool "json:\"google\""
			Facebook  bool "json:\"facebook\""
			Email     bool "json:\"email\""
			Saml      bool "json:\"saml\""
		}{false, false, false, false, false, true, false},
	}
	return res
}

func (n *NetlifyRessource) token(w http.ResponseWriter, r *http.Request) {
	n.uc.Token(w, r)
}

func (n *NetlifyRessource) user(w http.ResponseWriter, r *http.Request) {
	j, _, err := jwtauth.FromContext(r.Context())
	if err != nil {
		w.WriteHeader(500)
		return
	}
	email, ok := j.Get(tokens.ClaimEmail)
	if !ok {
		w.WriteHeader(500)
		return
	}
	err = render.Render(w, r, &userInfoResponse{
		Subject: j.Subject(),
		Email:   email.(string),
	})
	if err != nil {
		n.logger.Error("unable to render response", zap.Error(err))
	}
}

func (n *NetlifyRessource) settings(w http.ResponseWriter, r *http.Request) {
	//we just gonna abuse the full blown implementation here and wrap it in here
	render.Respond(w, r, newSettingsResponse())
}

func NewNetlifyRessource(logger *zap.Logger, c *connect.ConnnectRessource) *NetlifyRessource {
	return &NetlifyRessource{logger: logger, uc: c}
}

type userInfoResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

func (e *userInfoResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}
