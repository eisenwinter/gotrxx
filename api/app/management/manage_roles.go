package management

import (
	"net/http"

	"github.com/go-chi/render"
)

func (m *ManagementRessource) listRoles(w http.ResponseWriter, r *http.Request) {
	page := r.Context().Value(pageKey).(int)
	pageSize := r.Context().Value(pageSizeKey).(int)
	query := r.Context().Value(queryKey).(string)
	sort := r.Context().Value(sortKey).(string)

	roles, err := m.roleService.List(r.Context(), page, pageSize, query, sort)
	if err != nil {
		m.log.Error("error listing roles", "err", err)

		return
	}
	render.Respond(w, r, roles)
}
