package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
)

type Server struct {
	server *http.Server
	log    logging.Logger
}

func NewServer(
	cfg *config.Configuration,
	logger logging.Logger,
	issuer *tokens.TokenIssuer,
	rotator *tokens.TokenRotator,
	signInService *user.SigninService,
	userService *user.Service,
	authService *authorization.Service,
	appService *application.Service,
	registry *i18n.TranslationRegistry,
	fileSystems *config.FileSystems,
	verifier *tokens.TokenVerifier,
	manageUser *manage.UserService,
	manageAuth *manage.AuthorizationService,
	manageApplication *manage.ApplicationService,
	manageRole *manage.RoleService,
	manageInviteService *manage.InviteService) (*Server, error) {
	api, err := compose(logger.WithGroup("api"),
		cfg,
		issuer,
		signInService,
		userService,
		rotator,
		authService,
		appService,
		registry,
		fileSystems,
		manageUser,
		manageApplication,
		manageAuth,
		manageRole,
		manageInviteService,
		verifier)
	if err != nil {
		return nil, err
	}
	bind := net.JoinHostPort(cfg.Server.Address, strconv.Itoa(cfg.Server.Port))
	srv := http.Server{
		Addr:              bind,
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return &Server{
		server: &srv,
		log:    logger,
	}, nil
}

// Start runs ListenAndServe on the http.Server with graceful shutdown.
func (srv *Server) Start() error {
	srv.log.Info("starting server")
	go func() {
		if err := srv.server.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()
	srv.log.Info("listening", "addr", srv.server.Addr)

	quit := make(chan os.Signal, 1)
	//nolint
	signal.Notify(quit, os.Interrupt)
	sig := <-quit
	srv.log.Info("shutting down", "signal", sig)

	if err := srv.server.Shutdown(context.Background()); err != nil {
		srv.log.Error("graceful shutdown failed", "err", err)
		return err
	}
	srv.log.Info("graceful shutdown completed")
	return nil
}
