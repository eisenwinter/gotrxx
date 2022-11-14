package account

import (
	"html/template"
	"io/fs"

	"go.uber.org/zap"
)

func mustLoadTemplate(fs fs.FS, location string, logger *zap.Logger) (*template.Template, error) {
	template, err := template.ParseFS(fs, location)
	if err != nil {
		return nil, err
	}
	return template, nil
}
