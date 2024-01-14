package basic

import (
	"encoding/base64"
	"errors"
	"github.com/n0rdy/proteus/httpserver/logger"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/auth/db"
	"strings"
)

const basicAuthHeaderPrefix = "Basic "

type Service struct {
	adb *db.AuthDb
}

func NewService(adb *db.AuthDb) *Service {
	return &Service{adb: adb}
}

func (s *Service) CheckCredentials(basicAuthHeader string) bool {
	credsFromHeader, err := s.basicAuthHeaderToCredentials(basicAuthHeader)
	if err != nil {
		return false
	}

	creds := s.adb.GetOneBasicAuth(credsFromHeader.Username)
	if creds == nil {
		logger.Error("CheckCredentials: no credentials found for username: " + credsFromHeader.Username)
		return false
	}
	if creds.Password != credsFromHeader.Password {
		logger.Error("CheckCredentials: invalid password: expected: " + creds.Password + ", actual: " + credsFromHeader.Password)
		return false
	} else {
		return true
	}
}

func (s *Service) GetAll() []models.BasicAuthCredentialsInstance {
	return s.adb.GetAllBasicAuth()
}

func (s *Service) Add(credentials models.BasicAuthCredentialsInstance) error {
	return s.adb.InsertBasicAuth(credentials)
}

func (s *Service) DeleteAll() error {
	return s.adb.DeleteAllBasicAuth()
}

func (s *Service) Delete(username string) (found bool, err error) {
	creds := s.adb.GetOneBasicAuth(username)
	if creds == nil {
		return false, nil
	}
	return true, s.adb.DeleteOneBasicAuth(username)
}

func (s *Service) basicAuthHeaderToCredentials(basicAuthHeader string) (*models.BasicAuthCredentialsInstance, error) {
	basicAuthCredsFromHeader := strings.TrimPrefix(basicAuthHeader, basicAuthHeaderPrefix)
	decoded, err := base64.StdEncoding.DecodeString(basicAuthCredsFromHeader)
	if err != nil {
		logger.Error("basicAuthHeaderToCredentials: failed to decode basic auth header", err)
		return nil, err
	}

	usernameAndPassword := strings.Split(string(decoded), ":")
	if len(usernameAndPassword) != 2 {
		logger.Error("basicAuthHeaderToCredentials: invalid basic auth header")
		return nil, errors.New("invalid basic auth header")
	}
	return &models.BasicAuthCredentialsInstance{
		Username: usernameAndPassword[0],
		Password: usernameAndPassword[1],
	}, nil
}
