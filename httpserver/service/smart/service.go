package smart

import (
	"github.com/google/uuid"
	"github.com/n0rdy/proteus/httpserver/service/smart/db"
	"strings"
)

type Service struct {
	sdb *db.SmartDb
}

func NewService() (*Service, error) {
	sdb, err := db.NewSmartDb()
	if err != nil {
		return nil, err
	}
	return &Service{sdb: sdb}, nil
}

func (s *Service) Close() error {
	return s.sdb.Close()
}

func (s *Service) Get(domainPath string) (result interface{}, withId bool, err error) {
	res, err := s.sdb.Get(domainPath)
	if err != nil {
		return nil, false, err
	}
	if res == nil || len(res) == 0 {
		idFromPath := s.parseIdFromPath(domainPath)
		if idFromPath == "" {
			return nil, false, nil
		}
		domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
		resById, err := s.sdb.GetOne(domainPathWithoutId, idFromPath)
		if err != nil {
			return nil, false, err
		}
		if resById == nil || len(resById) == 0 {
			return nil, true, nil
		}
		return resById, true, nil
	}
	return res, false, nil
}

func (s *Service) Create(domainPath string, reqBody map[string]interface{}) (string, error) {
	return s.sdb.InsertOne(domainPath, reqBody)
}

func (s *Service) Update(domainPath string, reqBody map[string]interface{}) (bool, error) {
	idFromPath := s.parseIdFromPath(domainPath)
	if idFromPath == "" {
		return false, nil
	}
	domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
	return s.sdb.UpdateOne(domainPathWithoutId, idFromPath, reqBody)
}

func (s *Service) Delete(domainPath string) (bool, error) {
	idFromPath := s.parseIdFromPath(domainPath)
	if idFromPath == "" {
		return s.sdb.Delete(domainPath)
	}
	domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
	return s.sdb.DeleteOne(domainPathWithoutId, idFromPath)
}

func (s *Service) Clear() error {
	return s.sdb.Clear()
}

func (s *Service) parseIdFromPath(domainPath string) string {
	paths := strings.Split(domainPath, "/")
	if len(paths) < 3 {
		// 3 stands for: empty string, "domain", "id": e.g. "/books/123" -> ["", "books", "123"]
		// this is a minimum required length of the path to be able to parse the id
		return ""
	}

	// id is the last element of the path
	maybeId := paths[len(paths)-1]
	if _, err := uuid.Parse(maybeId); err != nil {
		// if the last element of the path is not a valid uuid, then it's not an id
		return ""
	}
	return maybeId
}
