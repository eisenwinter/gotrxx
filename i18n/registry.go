package i18n

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/jeremywohl/flatten/v2"
	"golang.org/x/text/language"
)

type translation map[string]*template.Template
type ressource map[string]translation
type localeDictionary map[string]ressource

type LangKey string

var ContextLangKey LangKey = "lang"

var ErrLanguageDoesntExist = errors.New("language does not exist")
var ErrRessourceDoesNotExist = errors.New("ressource does not exist")

type TranslationRegistry struct {
	dir      fs.FS //"templates/i18n"
	registry localeDictionary
	log      logging.Logger
	matcher  language.Matcher
}

func (t *TranslationRegistry) Matcher() language.Matcher {
	return t.matcher
}

func (t *TranslationRegistry) buildMatcher() {
	tags := make([]language.Tag, 0)
	for _, k := range t.Languages() {
		lang, err := language.Parse(k)
		if err != nil {
			t.log.Error("unable to parse language", "language", k)
			continue
		}
		tags = append(tags, lang)
	}
	t.matcher = language.NewMatcher(tags)
}

func (t *TranslationRegistry) Languages() []string {
	l := make([]string, 0)
	for k := range t.registry {
		l = append(l, k)
	}
	return l
}

func (t *TranslationRegistry) ContainsLanguage(language string) bool {
	for k := range t.registry {
		if k == language {
			return true
		}
	}
	return false
}

func NewTranslationRegistry(dir fs.FS, log logging.Logger) (*TranslationRegistry, error) {
	reg := TranslationRegistry{
		dir:      dir,
		log:      log,
		registry: make(localeDictionary),
	}
	err := reg.autoLoad()
	if err != nil {
		return nil, err
	}
	reg.buildMatcher()
	return &reg, nil
}

func (t *TranslationRegistry) CreateVoidTranslator(language string, ressource string) *Translator {
	d := make(translation)
	return &Translator{
		locale:    language,
		ressource: ressource,
		t:         d,
		registry:  t,
	}
}

func (t *TranslationRegistry) TranslatorFor(
	language string,
	ressource string,
) (*Translator, error) {
	if _, ok := t.registry[language]; !ok {
		return nil, ErrLanguageDoesntExist
	}
	if _, ok := t.registry[language][ressource]; !ok {
		return nil, ErrRessourceDoesNotExist
	}
	return &Translator{
		t:         t.registry[language][ressource],
		locale:    language,
		ressource: ressource,
		registry:  t,
	}, nil
}

func (t *TranslationRegistry) autoLoad() error {
	matches, err := fs.Glob(t.dir, "*.*.json")
	if err != nil {
		t.log.Error("could not load i18n files", "err", err)
		return err
	}
	t.log.Debug("loaded i18n files", "files", matches)
	return t.process(matches)
}

var jsonRegex = regexp.MustCompile(`[a-zA-Z]{2}\.json$`)

func (t *TranslationRegistry) process(files []string) error {
	for _, v := range files {
		t.log.Debug("processing language file", "file", v)
		_, file := filepath.Split(v)
		locale := jsonRegex.FindString(v)
		if locale != "" {
			name := strings.TrimSuffix(file, "."+locale)
			locale = strings.TrimSuffix(locale, ".json")
			res := t.registry[locale]
			if res == nil {
				t.registry[locale] = make(ressource)
				res = t.registry[locale]
			}
			file, err := fs.ReadFile(t.dir, v)

			if err != nil {
				t.log.Error(
					"could not read translation file",
					"err", err,
					"file", v,
				)
				return err
			}

			flat, err := flatten.FlattenString(string(file), "", flatten.DotStyle)
			if err != nil {
				t.log.Error(
					"skipping unparseable translation file",
					"err", err,
					"content", string(file),
					"file", v,
				)
				return err
			}
			tr := make(map[string]string)
			err = json.Unmarshal([]byte(flat), &tr)
			if err != nil {
				t.log.Error(
					"could not unmarshall translation file",
					"err", err,
					"file", v,
				)
				return err
			}
			final := make(translation)
			for k, v := range tr {
				parsed, err := template.New(k).Parse(v)
				if err != nil {
					t.log.Error("unable to parse template", "err", err, "file", v)
					return err
				}
				final[k] = parsed
			}
			res[name] = final
			t.log.Debug(
				"added translations",
				"ressource", name,
				"lang", locale,
			)
		}
	}
	return nil
}
