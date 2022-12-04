package account

import (
	"github.com/google/safehtml/template"

	"go.uber.org/zap"
)

func mustLoadTemplate(fs template.TrustedFS, location string, logger *zap.Logger) (*template.Template, error) {

	template, err := template.ParseFS(fs, location)
	if err != nil {
		logger.Error("unable to load template", zap.Error(err), zap.String("location", location))
		return nil, err
	}

	return template, nil
}
