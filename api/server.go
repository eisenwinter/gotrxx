package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"go.uber.org/zap"
)

type Server struct {
	server *http.Server
	log    *zap.Logger
}

func NewServer(
	cfg *config.Configuration,
	logger *zap.Logger,
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
	api, err := compose(logger.Named("api"),
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
	bind := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	srv := http.Server{
		Addr:    bind,
		Handler: api,
	}
	return &Server{
		server: &srv,
		log:    logger,
	}, nil
}

// Start runs ListenAndServe on the http.Server with graceful shutdown.
func (srv *Server) Start() {
	srv.log.Info("Starting server")
	go func() {
		if err := srv.server.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()
	srv.log.Info("Listening", zap.String("addr", srv.server.Addr))

	quit := make(chan os.Signal, 1)
	//nolint
	signal.Notify(quit, os.Interrupt)
	sig := <-quit
	srv.log.Info("Shutting down", zap.Any("signal", sig))

	if err := srv.server.Shutdown(context.Background()); err != nil {
		srv.log.Fatal("Graceful shutdown failed", zap.Error(err))
	}
	srv.log.Info("Graceful shutdown completed")
}
