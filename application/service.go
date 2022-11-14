package application

import (
	"context"
	"errors"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/db/tables"
	"go.uber.org/zap"
)

// ErrNotFound indicates the requested entity was not found
var ErrNotFound = errors.New("application not found")

type Service struct {
	log   *zap.Logger
	store *db.DataStore
}

func NewApplicationSevice(log *zap.Logger,
	store *db.DataStore) *Service {
	return &Service{
		log:   log,
		store: store,
	}
}

func (s *Service) build(table *tables.ApplicationTable) *Application {
	return ApplicationFromDbType(table)
}

func (s *Service) ApplicationById(ctx context.Context, id int) (*Application, error) {
	entry, err := s.store.ApplicationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.build(entry), nil
}

func (s *Service) ApplicationByClientID(ctx context.Context, clientID string) (*Application, error) {
	entry, err := s.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.build(entry), nil
}
