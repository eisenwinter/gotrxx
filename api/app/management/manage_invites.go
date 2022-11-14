package management

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
	"go.uber.org/zap"
)

func (m *ManagementRessource) listInvites(w http.ResponseWriter, r *http.Request) {
	page := r.Context().Value(pageKey).(int)
	pageSize := r.Context().Value(pageSizeKey).(int)
	query := r.Context().Value(queryKey).(string)
	sort := r.Context().Value(sortKey).(string)

	roles, err := m.inviteService.List(r.Context(), page, pageSize, query, sort)
	if err != nil {
		m.log.Error("error listing invites", zap.Error(err))

		return
	}
	render.Respond(w, r, roles)
}

func (m *ManagementRessource) createInvite(w http.ResponseWriter, r *http.Request) {
	var req *createInviteRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	token, err := m.userService.InviteUser(r.Context(), req.Email, req.Roles, req.Applications)
	success := true
	message := "Successfully created invite"
	var t *string
	if err != nil {
		success = false
		message = "Could create invite"
	} else {
		tmp := string(token)
		t = &tmp
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
		ID:      t,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}
