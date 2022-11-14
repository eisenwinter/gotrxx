package cmd

import (
	"log"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/mailing"
	"go.uber.org/zap"
)

func mustResolveUsableDataStore() *db.DataStore {
	var dataStore *db.DataStore
	var err error
	switch LoadedConfig.Database.Type {
	case "sqlite":
		dataStore, err = db.NewSqliteStore(TopLevelLogger.Named("database"), LoadedConfig.Database)
	case "mysql":
		dataStore, err = db.NewMysqlStore(TopLevelLogger.Named("database"), LoadedConfig.Database)
	case "pg":
		dataStore, err = db.NewPostgrestore(TopLevelLogger.Named("database"), LoadedConfig.Database)
	default:
		log.Fatal("Unknown database type")
	}
	if err != nil {
		TopLevelLogger.Fatal("Failed to create datastore", zap.Error(err))
	}
	err = dataStore.EnsureUsable()
	if err != nil {
		TopLevelLogger.Fatal("Datastore is unusable", zap.Error(err))
	}
	return dataStore
}

func mustResolveTranslationRegistry() *i18n.TranslationRegistry {
	registry, err := i18n.NewTranslationRegistry(FileSystemsConfig.Templates, TopLevelLogger.Named("i18n"))
	if err != nil {
		TopLevelLogger.Fatal("Failed to load translation files", zap.Error(err))
	}
	return registry
}

func bootstrapDispatcher(auditor db.Auditor) *events.Dispatcher {
	dispatcher := events.NewDispatcher(TopLevelLogger.Named("event_dispatcher"))
	//bootstrap listeners
	dbLayer := db.BootstrapListeners(auditor, TopLevelLogger.Named("event_listener"))
	dispatcher.Register(dbLayer...)
	return dispatcher
}

func mustResolveMailer(registry *i18n.TranslationRegistry) *mailing.Mailer {
	mailer, err := mailing.NewMailer(TopLevelLogger.Named("mailer"), LoadedConfig, registry, FileSystemsConfig.Templates)
	if err != nil {
		TopLevelLogger.Fatal("Failed to create mailer", zap.Error(err))
	}
	return mailer
}
