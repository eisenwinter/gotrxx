package tables

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// MapStructure is a map-like structure that may be stored in a persistent store
type MapStructure map[string]interface{}

// Value returns the map structures value
func (m MapStructure) Value() (driver.Value, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return driver.Value(""), err
	}
	return driver.Value(string(data)), nil
}

// Scan allows to scan a map structure
func (m MapStructure) Scan(src interface{}) error {
	var source []byte
	switch v := src.(type) {
	case string:
		source = []byte(v)
	case []byte:
		source = v
	default:
		if v != nil {
			return fmt.Errorf("error scanning json value: %+v", src)
		}
		source = []byte("{}")

	}
	if len(source) == 0 {
		source = []byte("{}")
	}
	return json.Unmarshal(source, &m)
}
