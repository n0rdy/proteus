package smart

import (
	"github.com/google/uuid"
	"github.com/n0rdy/proteus/httpserver/service/smart/db"
	"strings"
)

type SmartService struct {
	db *db.InMemorySmartDb
}

func NewSmartService() *SmartService {
	return &SmartService{
		db: db.NewInMemoryDB(),
	}
}

func (ss *SmartService) Get(domainPath string) (result interface{}, withId bool) {
	res := ss.db.Select(domainPath)
	if res == nil || len(res) == 0 {
		idFromPath := ss.parseIdFromPath(domainPath)
		if idFromPath == "" {
			return nil, false
		}
		domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
		resById := ss.db.SelectById(domainPathWithoutId, idFromPath)
		if resById == nil || len(res) == 0 {
			return nil, true
		}
		return resById, true
	}
	return res, false
}

func (ss *SmartService) Create(domainPath string, reqBody map[string]interface{}) db.SmartId {
	return ss.db.Insert(domainPath, reqBody)
}

func (ss *SmartService) Update(domainPath string, reqBody map[string]interface{}) bool {
	idFromPath := ss.parseIdFromPath(domainPath)
	if idFromPath == "" {
		return false
	}
	domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
	return ss.db.Update(domainPathWithoutId, idFromPath, reqBody)
}

func (ss *SmartService) Delete(domainPath string) bool {
	idFromPath := ss.parseIdFromPath(domainPath)
	if idFromPath == "" {
		return false
	}
	domainPathWithoutId := strings.TrimSuffix(domainPath, "/"+string(idFromPath))
	return ss.db.Delete(domainPathWithoutId, idFromPath)
}

func (ss *SmartService) parseIdFromPath(domainPath string) db.SmartId {
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
