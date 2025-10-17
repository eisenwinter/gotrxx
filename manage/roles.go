package manage

import (
	"context"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/eisenwinter/gotrxx/pkg/logging"
)

type RoleService struct {
	store      *db.DataStore
	log        logging.Logger
	dispatcher *events.Dispatcher
}

func (r *RoleService) List(
	ctx context.Context,
	page int,
	pageSize int,
	q string,
	sort string,
) (*PaginationResponse, error) {
	apps, total, err := r.store.Roles(
		ctx,
		db.ListOptions{Page: page, PageSize: pageSize, Query: q, Sort: sort},
	)
	if err != nil {
		return nil, err
	}
	dtos := make([]*RoleDTO, 0)
	for _, v := range apps {
		dtos = append(dtos, roleDTOfromDB(v))
	}
	return &PaginationResponse{
		Total:   total,
		Entries: dtos,
	}, nil
}

func (r *RoleService) CreateRole(ctx context.Context, name string) (int, error) {
	id, err := r.store.AddRole(ctx, name)
	if err != nil {
		return id, err
	}
	r.dispatcher.Dispatch(&event.RoleCreated{Role: name})
	return id, nil
}

func (r *RoleService) DeleteRole(ctx context.Context, name string) error {
	err := r.store.DeleteRole(ctx, name)
	if err != nil {
		return err
	}
	r.dispatcher.Dispatch(&event.RoleDeleted{Role: name})
	return nil
}

func NewRoleService(store *db.DataStore,
	log logging.Logger,
	dispatcher *events.Dispatcher) *RoleService {

	return &RoleService{
		store:      store,
		log:        log,
		dispatcher: dispatcher,
	}
}
