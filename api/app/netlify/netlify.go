package netlify

import (
	"net/http"

	"github.com/eisenwinter/gotrxx/api/app/connect"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"

	"go.uber.org/zap"
)

const NetlifyClientID = "netlify-gotrue"

type NetlifyRessource struct {
	logger *zap.Logger
	//nelitfy ressource just wraps the underlying connect ressource
	uc      *connect.ConnnectRessource
	rotator *tokens.TokenRotator
}

func (n *NetlifyRessource) Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(render.SetContentType(render.ContentTypeJSON))
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
		gr.Post("/logout", n.logout)
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
	grant := r.FormValue("grant_type")
	if grant != "password" {
		err := render.Render(w, r, &errorResponse{Error: "invalid_grant", StatusCode: http.StatusBadRequest, ErrorDescription: "invalid grant_type for .netlify endpoint"})
		if err != nil {
			n.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}

	username := r.FormValue("username")
	if username == "" {
		err := render.Render(w, r, &errorResponse{Error: "invalid_request", StatusCode: http.StatusBadRequest, ErrorDescription: "username field not supplied"})
		if err != nil {
			n.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	password := r.FormValue("password")
	if password == "" {
		err := render.Render(w, r, &errorResponse{Error: "invalid_request", StatusCode: http.StatusBadRequest, ErrorDescription: "password field not supplied"})
		if err != nil {
			n.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")
	req := &connect.PasswordGrantTokenRequest{
		Username:          username,
		Password:          password,
		ClientID:          NetlifyClientID,
		ClientSecret:      clientSecret,
		Scope:             scope,
		IssueNetlifyToken: true,
	}
	n.uc.PasswordGrant(req, w, r)
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
		Subject:      j.Subject(),
		Email:        email.(string),
		ID:           j.Subject(),
		AppMetaData:  map[string]string{},
		UserMetaData: map[string]string{},
	})
	if err != nil {
		n.logger.Error("unable to render response", zap.Error(err))
	}
}

func (n *NetlifyRessource) logout(w http.ResponseWriter, r *http.Request) {
	n.logger.Debug("Netlify logout called")
	j, _, err := jwtauth.FromContext(r.Context())
	if err != nil {
		w.WriteHeader(500)
		return
	}
	autId, ok := j.Get(tokens.ClaimAuthorization)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		n.logger.Error("no authorization id in JWT")
		return
	}
	id, err := uuid.Parse(autId.(string))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		n.logger.Error("malformed authorization id in JWT")
		return
	}
	err = n.rotator.RevokeCommonTokensForAuthorization(r.Context(), id)
	if err != nil {
		n.logger.Error("Could not revoked all common tokens for authorization", zap.Error(err), zap.String("authorization_id", id.String()))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (n *NetlifyRessource) settings(w http.ResponseWriter, r *http.Request) {
	//we just gonna abuse the full blown implementation here and wrap it in here
	render.Respond(w, r, newSettingsResponse())
}

func NewNetlifyRessource(logger *zap.Logger, c *connect.ConnnectRessource, rotator *tokens.TokenRotator) *NetlifyRessource {
	return &NetlifyRessource{logger: logger, uc: c, rotator: rotator}
}

type userInfoResponse struct {
	Subject      string            `json:"sub"`
	Email        string            `json:"email"`
	ID           string            `json:"id"`
	AppMetaData  map[string]string `json:"app_metadata"`
	UserMetaData map[string]string `json:"user_metadata"`
}

func (e *userInfoResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type errorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	StatusCode       int    `json:"-"`
}

func (e *errorResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.StatusCode)
	return nil
}
