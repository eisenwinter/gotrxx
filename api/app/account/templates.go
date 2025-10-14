package account

import (
	"path/filepath"
	"strings"

	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/google/safehtml/template"
)

func mustLoadTemplate(
	fs template.TrustedFS,
	location string,
	logger logging.Logger,
) (*template.Template, error) {
	plainName := strings.TrimSuffix(filepath.Base(location), ".gohtml")
	t, err := template.New(plainName).ParseFS(fs, "components/*.gohtml", location, "layout.gohtml")
	if err != nil {
		logger.Debug("unable to load template trying fallback", "err", err, "location", location)
		// maintaing backwards compatibility for .html extension
		// as some users may have customized templates with .html extension
		if len(location) > 7 && location[len(location)-7:] == ".gohtml" {
			htmlLocation := location[:len(location)-7] + ".html"
			t, err = template.New(plainName).ParseFS(fs, htmlLocation)
			if err != nil {
				logger.Error("unable to load template with either extension", "err", err, "location", location)
				return nil, err
			}
		} else {
			logger.Error("unable to load template", "err", err, "location", location)
			return nil, err
		}
	} else {
		t, err = t.Parse("{{template \"layout\" .}}")
		if err != nil {
			logger.Error("unable to parse layout into template", "err", err, "location", location)
			return nil, err
		}
	}

	return t, nil
}
