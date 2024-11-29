package cmd

import (
	"log"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/mailing"
)

func mustResolveUsableDataStore() *db.DataStore {
	var dataStore *db.DataStore
	var err error
	switch LoadedConfig.Database.Type {
	case "sqlite":
		dataStore, err = db.NewSqliteStore(TopLevelLogger.WithGroup("database"), LoadedConfig.Database)
	case "mysql":
		dataStore, err = db.NewMysqlStore(TopLevelLogger.WithGroup("database"), LoadedConfig.Database)
	case "pg":
		dataStore, err = db.NewPostgrestore(TopLevelLogger.WithGroup("database"), LoadedConfig.Database)
	default:
		log.Fatal("unknown database type")
	}
	if err != nil {
		TopLevelLogger.Error("failed to create datastore", "err", err)
		panic("failed to create datastore")
	}
	err = dataStore.EnsureUsable()
	if err != nil {
		TopLevelLogger.Error("datastore is unusable", "err", err)
		panic("datastore is unusable")
	}
	return dataStore
}

func mustResolveTranslationRegistry() *i18n.TranslationRegistry {
	registry, err := i18n.NewTranslationRegistry(
		FileSystemsConfig.I18n,
		TopLevelLogger.WithGroup("i18n"),
	)
	if err != nil {
		TopLevelLogger.Error("failed to load translation files", "err", err)
		panic("failed to load translation files")
	}
	return registry
}

func bootstrapDispatcher(auditor db.Auditor) *events.Dispatcher {
	dispatcher := events.NewDispatcher(TopLevelLogger.WithGroup("event_dispatcher"))
	//bootstrap listeners
	dbLayer := db.BootstrapListeners(auditor, TopLevelLogger.WithGroup("event_listener"))
	dispatcher.Register(dbLayer...)
	return dispatcher
}

func mustResolveMailer(registry *i18n.TranslationRegistry) *mailing.Mailer {
	mailer, err := mailing.NewMailer(
		TopLevelLogger.WithGroup("mailer"),
		LoadedConfig,
		registry,
		FileSystemsConfig.Email,
	)
	if err != nil {
		TopLevelLogger.Error("failed to create mailer", "err", err)
		panic("failed to create mailer")
	}
	return mailer
}
