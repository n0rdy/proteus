package apikey

import (
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/auth/db"
	"github.com/n0rdy/proteus/logger"
)

type Service struct {
	adb *db.AuthDb
}

func NewService(adb *db.AuthDb) *Service {
	return &Service{adb: adb}
}

func (s *Service) Close() error {
	return s.adb.Close()
}

func (s *Service) CheckCredentials(creds models.ApiKeyAuthCredentialsInstance) bool {
	credsFromDb := s.adb.GetOneApiKeyAuth(creds.KeyName)
	if credsFromDb == nil {
		logger.Error("CheckCredentials: no credentials found for key name: " + creds.KeyName)
		return false
	}
	if credsFromDb.KeyValue != creds.KeyValue {
		logger.Error("CheckCredentials: invalid key value: expected: " + credsFromDb.KeyValue + ", actual: " + creds.KeyValue)
		return false
	} else {
		return true
	}
}

func (s *Service) GetAll() []models.ApiKeyAuthCredentialsInstance {
	return s.adb.GetAllApiKeyAuth()
}

func (s *Service) Add(credentials models.ApiKeyAuthCredentialsInstance) error {
	return s.adb.InsertApiKeyAuth(credentials)
}

func (s *Service) DeleteAll() error {
	return s.adb.DeleteAllApiKeyAuth()
}

func (s *Service) Delete(keyName string) (found bool, err error) {
	creds := s.adb.GetOneApiKeyAuth(keyName)
	if creds == nil {
		return false, nil
	}
	return true, s.adb.DeleteOneApiKeyAuth(keyName)
}
