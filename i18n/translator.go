package i18n

import (
	"fmt"
	"strings"
)

type Translator struct {
	t         translation
	locale    string
	ressource string
	registry  *TranslationRegistry
}

// Registry retruns the translation registry the Translator was created from
func (t *Translator) Registry() *TranslationRegistry {
	return t.registry
}

// T retrives the translation for the supplied key
func (t *Translator) T(key ...string) string {
	k := strings.Join(key, ".")
	res := t.t[k]
	if res == nil {
		return fmt.Sprintf("missing (%s): %s", t.locale, k)
	}
	buffer := new(strings.Builder)
	err := res.Execute(buffer, t)
	if err != nil {
		return fmt.Sprintf("error (%s): %s", t.locale, k)
	}
	return buffer.String()
}
