package management

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/go-chi/render"
	"go.uber.org/zap"
)

func (m *ManagementRessource) listApplications(w http.ResponseWriter, r *http.Request) {
	page := r.Context().Value(pageKey).(int)
	pageSize := r.Context().Value(pageSizeKey).(int)
	query := r.Context().Value(queryKey).(string)
	sort := r.Context().Value(sortKey).(string)

	apps, err := m.appService.List(r.Context(), page, pageSize, query, sort)
	if err != nil {
		m.log.Error("error listing applications", zap.Error(err))

		return
	}
	render.Respond(w, r, apps)
}

func (m *ManagementRessource) applicationsWithActiveAuthorizationsByUserID(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req *userIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	active, err := m.appService.WithActiveUserAuthorizations(r.Context(), req.ID)
	if err != nil {
		m.log.Error("error listing active applications by user authoriziation", zap.Error(err))

		return
	}
	render.Respond(w, r, active)
}

func (m *ManagementRessource) appByClientId(w http.ResponseWriter, r *http.Request) {
	c := r.URL.Query().Get("client_id")
	app, err := m.appService.ByClientID(r.Context(), c)
	if err != nil {
		m.log.Info("error loading application data", zap.Error(err))
		render.Respond(w, r, createError("internal server error", http.StatusInternalServerError))
		return
	}
	err = render.Render(w, r, app)
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) createApplication(w http.ResponseWriter, r *http.Request) {
	var req *createApplicationRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	t := 0
	switch req.Type {
	case "implicit_granted":
		t = 1
	case "explicit_granted":
		t = 2
	default:
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	id, err := m.appService.CreateApplication(
		r.Context(),
		req.ClientID,
		req.ClientSecret,
		req.Name,
		req.Flows,
		req.RedirectURIs,
		req.LogoutURIs,
		req.Confidentiality,
		req.Scopes,
		t,
		req.PKCE,
	)
	success := true
	message := "Successfully created application"
	var i *string
	if err != nil {
		success = false
		message = "Could create application"
	} else {
		tmp := fmt.Sprint(id)
		i = &tmp
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
		ID:      i,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) retireApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.RetireApplication(r.Context(), req.ID)
	success := true
	message := "Successfully retired application"
	if err != nil {
		success = false
		message = "Could retired application"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) purgeRetiredApllications(w http.ResponseWriter, r *http.Request) {
	err := m.appService.PurgeRetiredApplications(r.Context())
	success := true
	message := "Successfully purged retired applications"
	if err != nil {
		success = false
		message = "Could purge retired applications"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) addRedirectUriToApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDAndURIRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.AddRedirectURI(r.Context(), req.ID, req.URI)
	success := true
	message := "Successfully addedd redirect URI"
	if err != nil {
		success = false
		message = "Could not add redirect URI"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) removeRedirectURIFromApplication(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req *clientIDAndURIRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.RemoveRedirectURI(r.Context(), req.ID, req.URI)
	success := true
	message := "Successfully removed redirect URI"
	if err != nil {
		success = false
		message = "Could not remove redirect URI"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}

}
func (m *ManagementRessource) addLogoutUriToApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDAndURIRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.AddLogoutURI(r.Context(), req.ID, req.URI)
	success := true
	message := "Successfully added logout URI"
	if err != nil {
		success = false
		message = "Could not add logout URI"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) removeLogoutUriFromApplication(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req *clientIDAndURIRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.appService.RemoveLogoutURI(r.Context(), req.ID, req.URI)
	success := true
	message := "Successfully removed logout URI"
	if err != nil {
		success = false
		message = "Could not remove logout URI"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) addFlowToApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDAndFlowRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.AddFlow(r.Context(), req.ID, application.FlowType(req.Flow))
	success := true
	message := "Successfully added flow"
	if err != nil {
		success = false
		message = "Could not add flow"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}

}

func (m *ManagementRessource) removeFlowFromApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDAndFlowRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.RemoveFlow(r.Context(), req.ID, application.FlowType(req.Flow))
	success := true
	message := "Successfully removed flow"
	if err != nil {
		success = false
		message = "Could not remove flow"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) enablePKCEForApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.appService.TogglePKCE(r.Context(), req.ID, true)
	success := true
	message := "Successfully enabled PKCE"
	if err != nil {
		success = false
		message = "Could not enable PKCE"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) disablePKCEForApplication(w http.ResponseWriter, r *http.Request) {
	var req *clientIDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}
	err = m.appService.TogglePKCE(r.Context(), req.ID, false)
	success := true
	message := "Successfully disabled PKCE"
	if err != nil {
		success = false
		message = "Could not disable PKCE"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func (m *ManagementRessource) updateSecretOfApplication(w http.ResponseWriter, r *http.Request) {
	var req *setApplicationSecretRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		m.log.Info("invalid payload data", zap.Error(err))
		render.Respond(w, r, createError("invalid payload", http.StatusBadRequest))
		return
	}

	err = m.appService.SetSecret(r.Context(), req.ID, req.Secret)
	success := true
	message := "Successfully set secret"
	if err != nil {
		success = false
		message = "Could not set secret"
	}
	err = render.Render(w, r, &genericSuccessResponse{
		Success: success,
		Message: message,
	})
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}
