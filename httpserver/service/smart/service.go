package smart

import (
	"github.com/google/uuid"
	"github.com/n0rdy/proteus/httpserver/service/smart/db"
	"strings"
)

type Service struct {
	db *db.InMemorySmartDb
}

func NewService() *Service {
	return &Service{
		db: db.NewInMemoryDB(),
	}
}

func (s *Service) Get(domainPath string) (result interface{}, withId bool) {
	res := s.db.Select(domainPath)
	if res == nil || len(res) == 0 {
		idFromPath := s.parseIdFromPath(domainPath)
		if idFromPath == "" {
			return nil, false
		}
		domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
		resById := s.db.SelectById(domainPathWithoutId, idFromPath)
		if resById == nil || len(res) == 0 {
			return nil, true
		}
		return resById, true
	}
	return res, false
}

func (s *Service) Create(domainPath string, reqBody map[string]interface{}) db.SmartId {
	return s.db.Insert(domainPath, reqBody)
}

func (s *Service) Update(domainPath string, reqBody map[string]interface{}) bool {
	idFromPath := s.parseIdFromPath(domainPath)
	if idFromPath == "" {
		return false
	}
	domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
	return s.db.Update(domainPathWithoutId, idFromPath, reqBody)
}

func (s *Service) Delete(domainPath string) bool {
	idFromPath := s.parseIdFromPath(domainPath)
	if idFromPath == "" {
		return s.db.Delete(domainPath)
	}
	domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
	return s.db.DeleteById(domainPathWithoutId, idFromPath)
}

func (s *Service) Clear() {
	s.db.Clear()
}

func (s *Service) parseIdFromPath(domainPath string) db.SmartId {
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
	return db.SmartId(maybeId)
}
