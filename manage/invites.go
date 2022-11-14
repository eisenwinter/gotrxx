package manage

import (
	"context"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"go.uber.org/zap"
)

type InviteService struct {
	store      *db.DataStore
	log        *zap.Logger
	dispatcher *events.Dispatcher
}

func (i *InviteService) List(ctx context.Context, page int, pageSize int, q string, sort string) (*PaginationResponse, error) {
	invites, total, err := i.store.Invites(ctx, db.ListOptions{Page: page, PageSize: pageSize, Query: q, Sort: sort})
	if err != nil {
		return nil, err
	}
	dtos := make([]*InviteDTO, 0)
	for _, v := range invites {
		//Todo: reconsider 1:n querrying - this is kind of rough
		data, err := i.store.InviteData(ctx, v.Code)
		if err != nil {
			continue
		}
		dtos = append(dtos, inviteDTOfromDB(v, data))
	}
	return &PaginationResponse{
		Total:   total,
		Entries: dtos,
	}, nil
}

func NewInviteService(store *db.DataStore,
	log *zap.Logger,
	dispatcher *events.Dispatcher) *InviteService {

	return &InviteService{
		store:      store,
		log:        log,
		dispatcher: dispatcher,
	}
}
