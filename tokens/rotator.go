package tokens

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"crypto/sha256"
	b64 "encoding/base64"
)

type CommonTokenUpdater interface {
	RevokeCommonTokensForAuthorization(ctx context.Context, authorizationID uuid.UUID) (int, error)
	CommonTokenDetails(
		ctx context.Context,
		tokenType string,
		token string,
	) (*db.CommonTokenDetails, error)
	RedeemCommonToken(ctx context.Context, tokenType string, token string) error
	RevokeCommonToken(ctx context.Context, tokenType string, token string) error
}

type Dispatcher interface {
	Dispatch(event events.Event)
}

type TokenRotator struct {
	updater    CommonTokenUpdater
	dispatcher Dispatcher
	log        *zap.Logger
}

func NewRotator(
	updater CommonTokenUpdater,
	dispatcher Dispatcher,
	log *zap.Logger) *TokenRotator {
	return &TokenRotator{
		updater:    updater,
		dispatcher: dispatcher,
		log:        log,
	}
}

var ErrChallengeFailed = errors.New("code verification challenge failed")
var ErrInvalidToken = errors.New("invalid or unknown token")
var ErrTokenRevoked = errors.New("token has been revoked")
var ErrTokenExpired = errors.New("token has expired")
var ErrTokenInvalidClientId = errors.New("token has been issued for different client id")
var ErrTokenNotFound = errors.New("unknown token")

// PreRotationChallenge needed to be done before rotating
func (t *TokenRotator) PreRotationChallenge(
	ctx context.Context,
	authorizationCode string,
	codeVerifier string,
) error {
	token, err := t.updater.CommonTokenDetails(
		ctx,
		string(AuthorizationCodeType),
		authorizationCode,
	)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return ErrTokenNotFound
		}
		return err

	}
	//https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
	method := token.CodeChallengeMethod()
	if method != "S256" {
		t.log.Warn("PKCE different then S256 received", zap.String("method", method))
		return errors.New("unspported challenge method detected")
	}
	hash := sha256.Sum256([]byte(codeVerifier))
	encoded := b64.URLEncoding.EncodeToString(hash[:])
	//trim padding
	encoded = strings.TrimRight(encoded, "=")
	if encoded != token.CodeChallenge() {
		return ErrChallengeFailed
	}
	return nil
}

func (t *TokenRotator) RevokeCommonTokensForAuthorization(
	ctx context.Context,
	autID uuid.UUID,
) error {
	_, err := t.updater.RevokeCommonTokensForAuthorization(ctx, autID)
	return err
}

func (t *TokenRotator) RevokeCommonToken(
	ctx context.Context,
	tokenType CommonTokenType,
	token string,
	autID uuid.UUID,
) error {
	details, err := t.updater.CommonTokenDetails(ctx, string(tokenType), token)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return ErrTokenNotFound
		}
		t.log.Error("could not load common token details", zap.Error(err))
		return err
	}
	if details.AuthorizationId != autID {
		t.log.Warn("supplied authorization does not match common token authorisation")
		return ErrInvalidToken
	}
	if details.RevokedAt != nil {
		t.log.Warn("revoked token has been used")
		return ErrTokenRevoked
	}
	if details.RedeemedAt != nil {
		t.log.Warn("redeemed token used - this one has been already rotated! revocation starting")
		t.dispatcher.Dispatch(&event.TokenAlreadyRedeemed{TokenID: details.ID,
			AuthorizationID: details.AuthorizationId,
			UserID:          details.UserID,
			Token:           details.Token,
			TokenType:       string(details.TokenType)})
		total, err := t.updater.RevokeCommonTokensForAuthorization(ctx, details.AuthorizationId)
		if err != nil {
			t.log.Error(
				"could not revoke tokens for authorization",
				zap.Any("AuthorizationId", details.AuthorizationId),
			)
			return err
		}
		t.log.Warn("revoked all tokens for authorization", zap.Int("revoked_count", total))
		return ErrTokenRevoked
	}
	if details.ExpiresAt.Before(time.Now().UTC()) {
		t.log.Info("expired token has been used")
		return ErrInvalidToken
	}
	err = t.updater.RevokeCommonToken(ctx, string(tokenType), token)
	if err != nil {
		t.log.Error("could not revoke token", zap.Error(err))
		return err
	}
	return nil
}

func (t *TokenRotator) RotateCommonToken(
	ctx context.Context,
	tokenType CommonTokenType,
	token string,
	clientID string,
) error {
	details, err := t.updater.CommonTokenDetails(ctx, string(tokenType), token)
	if err != nil {
		t.log.Error("could not load common token details", zap.Error(err))
		return err
	}
	if details.ClientID != clientID {
		t.log.Warn("wrong client id")
		return ErrTokenInvalidClientId
	}
	if details.RevokedAt != nil {
		t.log.Warn("revoked token has been used")
		return ErrTokenRevoked
	}
	if details.RedeemedAt != nil {
		t.log.Warn("redeemed token used - this one has been already rotated! revocation starting")
		t.dispatcher.Dispatch(&event.TokenAlreadyRedeemed{TokenID: details.ID,
			AuthorizationID: details.AuthorizationId,
			UserID:          details.UserID,
			Token:           details.Token,
			TokenType:       string(details.TokenType)})
		total, err := t.updater.RevokeCommonTokensForAuthorization(ctx, details.AuthorizationId)
		if err != nil {
			t.log.Error(
				"could not revoke tokens for authorization",
				zap.Any("AuthorizationId", details.AuthorizationId),
			)
			return err
		}
		t.log.Warn("revoked all tokens for authorization", zap.Int("revoked_count", total))
		return ErrTokenRevoked
	}
	if details.ExpiresAt.Before(time.Now().UTC()) {
		t.log.Info("expired token has been used")
		return ErrInvalidToken
	}
	err = t.updater.RedeemCommonToken(ctx, string(tokenType), token)
	if err != nil {
		t.log.Error("could not redeem token", zap.Error(err))
		return err
	}

	return nil
}
