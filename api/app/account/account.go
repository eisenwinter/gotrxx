package account

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

const gotrxxClientID = "$.gotrxx"
const jwtCookie = "__gotrxx"
const rememberMeCookie = "_gotrxx"

type AccountRessource struct {
	loginTmpl              *template.Template
	signUpTmpl             *template.Template
	userPageTmpl           *template.Template
	confirmTemplate        *template.Template
	errorTemplate          *template.Template
	recoverTemplate        *template.Template
	changeEmailTemplate    *template.Template
	changePasswordTemplate *template.Template
	fourOFourTemplate      *template.Template
	requestRecoverTmpl     *template.Template
	chageMfaTmpl           *template.Template
	mfaSetupTmpl           *template.Template
	inviteTmpl             *template.Template

	log         *zap.Logger
	userSignIn  *user.SigninService
	userService *user.Service

	cfg        *config.BehaviourConfiguration
	serverCfg  *config.ServerConfiguration
	autService *authorization.Service
	issuer     *tokens.TokenIssuer
	verifier   *tokens.TokenVerifier
	registry   *i18n.TranslationRegistry
	rotator    *tokens.TokenRotator
	statics    fs.FS
}

func (a *AccountRessource) Router() *chi.Mux {
	r := chi.NewRouter()

	antiForgery := csrf.Protect([]byte(a.serverCfg.CSRFToken))
	r.Use(antiForgery)

	r.Get("/", a.userPage)

	r.Get("/signin", a.signinPage)
	r.Post("/signin", a.signin)

	r.Get("/signup", a.signupPage)
	r.Post("/signup", a.signup)

	r.Post("/signout", a.signout)

	r.Get("/confirm", a.confirm)

	r.Get("/recover", a.recover)
	r.Post("/recover", a.recoverPassword)

	r.Get("/forgotten-password", a.forgottenPassword)
	r.Post("/forgotten-password", a.triggerPasswordRecovery)

	r.Get("/change-email", a.changeEmail)
	r.Post("/change-email", a.updateEmail)

	r.Get("/change-password", a.changePassword)
	r.Post("/change-password", a.updatePassword)

	r.Get("/change-mfa", a.mfa)
	r.Post("/provision-mfa", a.provisionMFA)
	r.Post("/set-mfa", a.setMFA)
	r.Post("/disable-mfa", a.disableMFA)

	r.Get("/change-language", a.changeLanguage)

	r.Get("/invite", a.invitePage)
	r.Post("/invite", a.sendInvite)

	fs := http.FileServer(noDirectoryListingFs{http.FS(a.statics)})
	r.Handle("/static/*", http.StripPrefix("/account/static/", fs))

	r.NotFound(a.fourOFour)
	return r
}

func (a *AccountRessource) canUserInvite(ctx context.Context, token jwt.Token) bool {
	if a.cfg.InviteOnly && a.cfg.InviteRole != nil {
		id := token.Subject()
		userid, err := uuid.Parse(id)
		if err == nil && a.userService.InRole(ctx, userid, *a.cfg.InviteRole) {
			return true
		}
	}
	return false
}

func (a *AccountRessource) currentLocale(ctx context.Context) string {
	locale := ctx.Value(i18n.ContextLangKey)
	if locale != nil && len(locale.(string)) == 2 {
		return locale.(string)
	}
	if len(a.cfg.DefaultLocale) == 2 {
		return a.cfg.DefaultLocale
	}
	return "en"
}

func (a *AccountRessource) getTranslatorFor(ctx context.Context, page string) *i18n.Translator {
	locale := a.currentLocale(ctx)
	res := fmt.Sprintf("page.%s", page)
	t, err := a.registry.TranslatorFor(locale, res)
	if err != nil {
		if errors.Is(i18n.ErrLanguageDoesntExist, err) {
			a.log.Error("[i18n] languages doesnt exist", zap.String("iso", locale))
		}
		if errors.Is(i18n.ErrRessourceDoesNotExist, err) {
			a.log.Error("[i18n] ressource doesnt exist", zap.String("ressource", res))
		}
		return a.registry.CreateVoidTranslator(locale, res)
	}
	return t
}

func (a *AccountRessource) signedInUser(w http.ResponseWriter, r *http.Request) (bool, jwt.Token) {
	tokenCookie, err := r.Cookie(jwtCookie)
	if err != nil {
		if errors.Is(http.ErrNoCookie, err) {
			a.log.Debug("account ressource: no jwt cookie", zap.Error(err))
			rememberMe, err := r.Cookie(rememberMeCookie)
			if err != nil {
				return false, nil
			}
			token, err := a.exchangeRememberMeToken(r.Context(), rememberMe.Value, w)
			if err != nil {
				return false, nil
			}
			return true, token
		}
		a.log.Debug("account ressource: error reading cookie", zap.Error(err))
		return false, nil
	}
	a.log.Debug("account ressource: reading jwt")
	clearCookie := func() {
		c := &http.Cookie{
			Name:     jwtCookie,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   true,
		}
		http.SetCookie(w, c)

		r := &http.Cookie{
			Name:     rememberMeCookie,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   true,
		}
		http.SetCookie(w, r)
	}

	token, err := a.verifier.ParseAndValidateAccessToken(tokenCookie.Value)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired()) {
			rememberMe, rerr := r.Cookie(rememberMeCookie)
			if rerr != nil {
				clearCookie()
				return false, nil
			}
			if rememberMe.Value != "" {
				token, err := a.exchangeRememberMeToken(r.Context(), rememberMe.Value, w)
				if err != nil {
					return false, nil
				}
				return true, token
			}
		}
		a.log.Error("account ressrouce: unexpected JWT error after reading cookie", zap.Error(err))
		clearCookie()
		return false, nil
	}
	return true, token
}

func (a *AccountRessource) fourOFour(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)

	a.view(r.Context(), a.fourOFourTemplate, map[string]interface{}{}, w)
}

func (a *AccountRessource) exchangeRememberMeToken(
	ctx context.Context,
	token string,
	w http.ResponseWriter,
) (jwt.Token, error) {
	err := a.rotator.RotateCommonToken(ctx, tokens.RememberMeTokenType, token, gotrxxClientID)
	if err != nil {
		return nil, err
	}
	auth, err := a.autService.AuthorizationByCommonToken(
		ctx,
		string(tokens.RememberMeTokenType),
		token,
	)
	if err != nil {
		return nil, err
	}
	user, err := a.userSignIn.SignInByIDFromToken(
		ctx,
		auth.UserID(),
		string(tokens.RememberMeTokenType),
	)
	if err != nil {
		return nil, err
	}
	return a.issueUserCookie(ctx, user, auth, true, w)
}

func (a *AccountRessource) issueUserCookie(
	ctx context.Context,
	user *user.SignedInUser,
	auth *authorization.Authorization,
	rememberMe bool,
	w http.ResponseWriter,
) (jwt.Token, error) {
	t, err := a.issuer.IssueAccessTokenForUser(
		user,
		auth.ID(),
		auth.Application().ClientID(),
		auth.Scopes(),
	)
	if err != nil {
		a.log.Error("user login page: failed to issue a new access token", zap.Error(err))
		return nil, err
	}
	signed, err := a.issuer.Sign(t)
	if err != nil {
		a.log.Error("user login page: failed to sign a access token", zap.Error(err))
		return nil, err
	}
	expires := int(t.Expiration().Sub(time.Now().UTC()).Seconds())
	cookie := http.Cookie{Name: jwtCookie,
		Value:    string(signed),
		Path:     "/",
		Expires:  t.Expiration(),
		MaxAge:   expires,
		HttpOnly: true,
		Secure:   true}
	http.SetCookie(w, &cookie)

	if rememberMe && a.issuer.RememberMeDuration() > 0 {
		duration := int(a.issuer.RememberMeDuration().Seconds())
		expiry := time.Now().UTC().Add(a.issuer.RememberMeDuration())
		rememberMeToken, err := a.issuer.IssueRememberMeToken(ctx, auth.ID())
		if err != nil {
			return nil, err
		}
		rem := http.Cookie{Name: rememberMeCookie,
			Value:    string(rememberMeToken),
			Path:     "/",
			Expires:  expiry,
			MaxAge:   duration,
			HttpOnly: true,
			Secure:   true}
		http.SetCookie(w, &rem)
	}
	return t, nil
}

func (a *AccountRessource) userPage(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	email, _ := token.Get(tokens.ClaimEmail)

	a.view(r.Context(), a.userPageTmpl, map[string]interface{}{
		"email":          email,
		"canInvite":      a.canUserInvite(r.Context(), token),
		csrf.TemplateTag: csrf.TemplateField(r)}, w)
}

func (a *AccountRessource) view(
	ctx context.Context,
	tmpl *template.Template,
	viewData map[string]interface{},
	w http.ResponseWriter,
) {
	name := strings.TrimSuffix(path.Base(tmpl.Name()), ".html")
	viewData["i18n"] = a.getTranslatorFor(ctx, name)
	err := tmpl.Execute(w, viewData)
	if err != nil {
		a.log.Error(
			"unable to render template for page",
			zap.String("template", name),
			zap.Error(err),
		)
	}
}

func (a *AccountRessource) changeLanguage(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("change lang: ParseForm failed", zap.Error(err))
	}
	returnURL := r.FormValue("return_url")
	lang := strings.ToLower(r.FormValue("lang"))
	if a.registry.ContainsLanguage(lang) {

		cookie := &http.Cookie{
			Name:     string(i18n.ContextLangKey),
			Value:    lang,
			Expires:  time.Now().Add(356 * 24 * time.Hour),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}

	http.Redirect(w, r, sanitizeReturnURL(returnURL, "/account/"), http.StatusFound)
}

func (a *AccountRessource) signout(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("signin: ParseForm failed", zap.Error(err))
	}

	jwtc, err := r.Cookie(jwtCookie)
	if err != nil {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	if jwtc.Value == "" {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	token, err := a.verifier.ParseAndValidateAccessToken(jwtc.Value)

	c := &http.Cookie{
		Name:     jwtCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, c)
	if err != nil {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	remember, err := r.Cookie(rememberMeCookie)
	rc := &http.Cookie{
		Name:     rememberMeCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, rc)

	if err != nil {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	if remember.Value == "" || remember.Expires.Before(time.Now()) {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	autID, ok := token.Get(tokens.ClaimAuthorization)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	id, err := uuid.Parse(autID.(string))
	if err != nil {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	err = a.rotator.RevokeCommonToken(r.Context(), tokens.RememberMeTokenType, remember.Value, id)
	if err != nil {
		if errors.Is(tokens.ErrTokenNotFound, err) {
			a.log.Warn("could not find remember me token to revoke")
		} else {
			a.log.Error("could not revoke remember me token on sign out", zap.Error(err))
		}

	}
	returnURL := r.FormValue("return_url")
	http.Redirect(w, r, sanitizeReturnURL(returnURL, "/account/signin"), http.StatusFound)

}

func sanitizeReturnURL(returnURL string, fallback string) string {
	parsed, err := url.ParseRequestURI(returnURL)
	if err != nil {
		return fallback
	}
	return parsed.RequestURI()
}

func NewAccountRessource(log *zap.Logger,
	userSignIn *user.SigninService,
	cfg *config.BehaviourConfiguration,
	userService *user.Service,
	autService *authorization.Service,
	issuer *tokens.TokenIssuer,
	registry *i18n.TranslationRegistry,
	rotator *tokens.TokenRotator,
	serverCfg *config.ServerConfiguration,
	fsConfig *config.FileSystems,
	verifier *tokens.TokenVerifier) *AccountRessource {

	loginTmpl, err := mustLoadTemplate(fsConfig.Templates, "templates/signin.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "signin.html"),
			zap.Error(err),
		)
	}
	signUpTmpl, err := mustLoadTemplate(fsConfig.Templates, "templates/signup.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "signup.html"),
			zap.Error(err),
		)
	}
	userPageTmpl, err := mustLoadTemplate(fsConfig.Templates, "templates/user.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "user.html"),
			zap.Error(err),
		)
	}
	confirmTemplate, err := mustLoadTemplate(fsConfig.Templates, "templates/confirm.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "confirm.html"),
			zap.Error(err),
		)
	}
	recoverTemplate, err := mustLoadTemplate(
		fsConfig.Templates,
		"templates/recover_password.html",
		log,
	)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "recover_password.html"),
			zap.Error(err),
		)
	}
	requestRecoverTmpl, err := mustLoadTemplate(
		fsConfig.Templates,
		"templates/request_password_recovery.html",
		log,
	)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "request_password_recovery.html"),
			zap.Error(err),
		)
	}
	errorTemplate, err := mustLoadTemplate(fsConfig.Templates, "templates/error.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "error.html"),
			zap.Error(err),
		)
	}
	changePasswordTemplate, err := mustLoadTemplate(
		fsConfig.Templates,
		"templates/change_password.html",
		log,
	)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "change_password.html"),
			zap.Error(err),
		)
	}
	changeEmailTemplate, err := mustLoadTemplate(
		fsConfig.Templates,
		"templates/change_email.html",
		log,
	)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "change_email.html"),
			zap.Error(err),
		)
	}

	changeMfaTemplate, err := mustLoadTemplate(fsConfig.Templates, "templates/change_mfa.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "change_mfa.html"),
			zap.Error(err),
		)
	}

	provisionMfaTemplate, err := mustLoadTemplate(
		fsConfig.Templates,
		"templates/provision_mfa.html",
		log,
	)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "provision_mfa.html"),
			zap.Error(err),
		)
	}

	inviteTemplate, err := mustLoadTemplate(fsConfig.Templates, "templates/invite.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "invite.html"),
			zap.Error(err),
		)
	}

	fourOFour, err := mustLoadTemplate(fsConfig.Templates, "templates/404.html", log)
	if err != nil {
		log.Fatal(
			"unable to load required template file",
			zap.String("file", "404.html"),
			zap.Error(err),
		)
	}

	return &AccountRessource{
		loginTmpl:              loginTmpl,
		log:                    log,
		userSignIn:             userSignIn,
		signUpTmpl:             signUpTmpl,
		cfg:                    cfg,
		userService:            userService,
		userPageTmpl:           userPageTmpl,
		autService:             autService,
		issuer:                 issuer,
		recoverTemplate:        recoverTemplate,
		confirmTemplate:        confirmTemplate,
		errorTemplate:          errorTemplate,
		changeEmailTemplate:    changeEmailTemplate,
		changePasswordTemplate: changePasswordTemplate,
		registry:               registry,
		fourOFourTemplate:      fourOFour,
		rotator:                rotator,
		serverCfg:              serverCfg,
		statics:                fsConfig.StaticFolder,
		requestRecoverTmpl:     requestRecoverTmpl,
		chageMfaTmpl:           changeMfaTemplate,
		mfaSetupTmpl:           provisionMfaTemplate,
		inviteTmpl:             inviteTemplate,
		verifier:               verifier,
	}
}
