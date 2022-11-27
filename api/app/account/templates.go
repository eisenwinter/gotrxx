package account

import (
	"html/template"
	"io/fs"

	"go.uber.org/zap"
)

func mustLoadTemplate(fs fs.FS, location string, logger *zap.Logger) (*template.Template, error) {
	template, err := template.ParseFS(fs, location)
	if err != nil {
		logger.Error("unable to load template", zap.Error(err), zap.String("location", location))
		return nil, err
	}

	return template, nil
}
