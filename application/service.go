package application

import (
	"context"
	"errors"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/eisenwinter/gotrxx/pkg/logging"
)

// ErrNotFound indicates the requested entity was not found
var ErrNotFound = errors.New("application not found")

// ApplicationStorer handles access to the underlying datasource
type ApplicationStorer interface {
	ApplicationByID(ctx context.Context, id int) (*tables.ApplicationTable, error)
	ApplicationByClientID(
		ctx context.Context,
		clientID string,
	) (*tables.ApplicationTable, error)
}

type Service struct {
	log   logging.Logger
	store ApplicationStorer
}

func NewApplicationSevice(log logging.Logger,
	store ApplicationStorer) *Service {
	return &Service{
		log:   log,
		store: store,
	}
}

func (*Service) build(table *tables.ApplicationTable) *Application {
	return ApplicationFromDbType(table)
}

func (s *Service) ApplicationByID(ctx context.Context, id int) (*Application, error) {
	entry, err := s.store.ApplicationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.build(entry), nil
}

func (s *Service) ApplicationByClientID(
	ctx context.Context,
	clientID string,
) (*Application, error) {
	entry, err := s.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.build(entry), nil
}
