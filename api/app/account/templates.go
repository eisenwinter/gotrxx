package account

import (
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/google/safehtml/template"
)

func mustLoadTemplate(
	fs template.TrustedFS,
	location string,
	logger logging.Logger,
) (*template.Template, error) {

	template, err := template.ParseFS(fs, location)
	if err != nil {
		logger.Error("unable to load template", "err", err, "location", location)
		return nil, err
	}

	return template, nil
}
