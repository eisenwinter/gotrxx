package management

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (m *ManagementRessource) listUsers(w http.ResponseWriter, r *http.Request) {
	page := r.Context().Value(pageKey).(int)
	pageSize := r.Context().Value(pageSizeKey).(int)
	query := r.Context().Value(queryKey).(string)
	sort := r.Context().Value(sortKey).(string)

	apps, err := m.userService.List(r.Context(), page, pageSize, query, sort)
	if err != nil {
		m.log.Error("error listing users", zap.Error(err))

		return
	}
	render.Respond(w, r, apps)
}

func (m *ManagementRessource) userByID(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("id")
	id, err := uuid.Parse(u)
	if err != nil {
		m.log.Info("invalid query data for user by id", zap.Error(err))
		render.Respond(w, r, createError("invalid query data", http.StatusBadRequest))
		return
	}
	user, err := m.userService.ByID(r.Context(), id)
	if err != nil {
		m.log.Error("error getting user by id", zap.Error(err))
		render.Respond(w, r, createError("internal server error", http.StatusInternalServerError))
		return
	}
	render.Respond(w, r, user)
}

func (m *ManagementRessource) confirmUser(w http.ResponseWriter, r *http.Request) {
	var req *userIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data for confirm user", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.userService.ConfirmUser(r.Context(), req.ID)
	success := true
	message := "Successfully confirmed user"
	if err != nil {
		success = false
		message = "Unable to confirm user"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) addUserToRole(w http.ResponseWriter, r *http.Request) {
	var req *userIDRoleRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.userService.AddUserToRole(r.Context(), req.ID, req.Role)
	success := true
	message := "Successfully added user to role"
	if err != nil {
		success = false
		message = "Could not add user to role"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) removeUserFromRole(w http.ResponseWriter, r *http.Request) {
	var req *userIDRoleRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.userService.RemoveUserFromRole(r.Context(), req.ID, req.Role)
	success := true
	message := "Successfully removed user from role"
	if err != nil {
		success = false
		message = "Could not remove user from role"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) banUser(w http.ResponseWriter, r *http.Request) {
	var req *userIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.userService.BanUser(r.Context(), req.ID)
	success := true
	message := "Successfully banned user"
	if err != nil {
		success = false
		message = "Unable to ban user"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) unbanUser(w http.ResponseWriter, r *http.Request) {
	var req *userIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data for unban user", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.userService.UnbanUser(r.Context(), req.ID)
	success := true
	message := "Successfully unbanned user"
	if err != nil {
		success = false
		message = "Unable to unban user"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) unlockUser(w http.ResponseWriter, r *http.Request) {
	var req *userIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data for unlock user", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.userService.UnlockUser(r.Context(), req.ID)
	success := true
	message := "Successfully unlocked user"
	if err != nil {
		success = false
		message = "Unable to unlock user"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}
