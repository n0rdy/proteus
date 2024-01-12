package db

import (
	"github.com/google/uuid"
)

// proteusExternalSmartId is a key appended to the request body to store the id of the smart object in the DB
const proteusExternalSmartIdKey = "proteusExternalSmartId"

type SmartId string

type InMemorySmartDb struct {
	data map[string]map[SmartId]map[string]interface{}
}

func NewInMemoryDB() *InMemorySmartDb {
	return &InMemorySmartDb{
		data: make(map[string]map[SmartId]map[string]interface{}),
	}
}

func (db *InMemorySmartDb) Select(domainPath string) []map[string]interface{} {
	res := make([]map[string]interface{}, 0)
	for _, v := range db.data[domainPath] {
		res = append(res, v)
	}
	return res
}

func (db *InMemorySmartDb) SelectById(domainPath string, id SmartId) map[string]interface{} {
	return db.data[domainPath][id]
}

func (db *InMemorySmartDb) Insert(domainPath string, reqBody map[string]interface{}) SmartId {
	id := SmartId(uuid.New().String())
	reqBody[proteusExternalSmartIdKey] = id

	if db.data[domainPath] == nil {
		db.data[domainPath] = make(map[SmartId]map[string]interface{})
	}
	db.data[domainPath][id] = reqBody
	return id
}

func (db *InMemorySmartDb) Update(domainPath string, id SmartId, reqBody map[string]interface{}) bool {
	_, ok := db.data[domainPath][id]
	if ok {
		reqBody[proteusExternalSmartIdKey] = id
		db.data[domainPath][id] = reqBody
	}
	return ok
}

func (db *InMemorySmartDb) DeleteById(domainPath string, id SmartId) bool {
	_, ok := db.data[domainPath][id]
	if ok {
		delete(db.data[domainPath], id)
	}
	return ok
}

func (db *InMemorySmartDb) Delete(domainPath string) bool {
	_, ok := db.data[domainPath]
	if ok {
		delete(db.data, domainPath)
	}
	return ok
}

func (db *InMemorySmartDb) Clear() {
	db.data = make(map[string]map[SmartId]map[string]interface{})
}
