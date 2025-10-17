package management

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
)

func (m *ManagementRessource) listAuthorizations(w http.ResponseWriter, r *http.Request) {
	page := r.Context().Value(pageKey).(int)
	pageSize := r.Context().Value(pageSizeKey).(int)
	query := r.Context().Value(queryKey).(string)
	sort := r.Context().Value(sortKey).(string)

	roles, err := m.authService.List(r.Context(), page, pageSize, query, sort)
	if err != nil {
		m.log.Error("error listing authoriziations", "err", err)

		return
	}
	render.Respond(w, r, roles)
}

func (m *ManagementRessource) activeAuthorizationsByUserID(w http.ResponseWriter, r *http.Request) {
	var req *userIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", "err", err)
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	active, err := m.authService.ActiveByUser(r.Context(), req.ID)
	if err != nil {
		m.log.Error("error listing active authoriziations by user", "err", err)

		return
	}
	render.Respond(w, r, active)
}

func (m *ManagementRessource) grantAuthorization(w http.ResponseWriter, r *http.Request) {
	var req *clientIDuserIDscopeRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", "err", err)
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.authService.GrantAuthorization(r.Context(), req.UserID, req.ClientID, req.Scope)
	success := true
	message := "Successfully granted authorization"
	if err != nil {
		success = false
		message = "Could not grant authorization"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", "err", err)
	}
}

func (m *ManagementRessource) revokeAuthorization(w http.ResponseWriter, r *http.Request) {
	var req *clientIDAndUserIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", "err", err)
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.authService.RevokeAuthorizationByClientIDAndUserID(
		r.Context(),
		req.ClientID,
		req.UserID,
	)
	success := true
	message := "Successfully revoked authorization"
	if err != nil {
		success = false
		message = "Could not revoke authorization"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", "err", err)
	}
}
