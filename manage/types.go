package manage

type PaginationResponse struct {
	Total   int         `json:"total"`
	Entries interface{} `json:"entries"`
}

func (*PaginationResponse) Render() {

}
