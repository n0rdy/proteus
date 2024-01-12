package db

import (
	"github.com/google/uuid"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/logger"
	"github.com/n0rdy/proteus/httpserver/utils"
	bolt "go.etcd.io/bbolt"
)

const (
	smartRestBucket = "REST"

	// proteusExternalSmartId is a key appended to the request body to store the id of the smart object in the DB
	proteusExternalSmartIdKey = "proteusExternalSmartId"
)

var smartBucketBytes = []byte(smartRestBucket)

type SmartDb struct {
	db *bolt.DB
}

func NewSmartDb() (*SmartDb, error) {
	boltDb, err := bolt.Open(utils.GetOsSpeificDbDir()+"proteus_smart.db", 0600, nil)
	if err != nil {
		return nil, err
	}

	err = boltDb.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists(smartBucketBytes)
		if err != nil {
			logger.Error("error on creating BoltDB bucket: "+smartRestBucket, err)
			return err
		}
		return nil
	})
	if err != nil {
		logger.Error("error on creating BoltDB bucket: "+smartRestBucket, err)
		return nil, err
	}

	return &SmartDb{db: boltDb}, nil
}

func (sdb *SmartDb) Close() error {
	return sdb.db.Close()
}

func (sdb *SmartDb) Get(domainPath string) ([]map[string]interface{}, error) {
	var smartInstance models.SmartInstance
	err := sdb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(smartBucketBytes)
		v := b.Get([]byte(sdb.toKey(domainPath)))
		if v == nil {
			return nil
		}
		return utils.Deserialize(v, &smartInstance)
	})
	if err != nil {
		logger.Error("error on getting value from BoltDB for key: "+domainPath, err)
		return nil, err
	}

	res := make([]map[string]interface{}, 0)
	for _, v := range smartInstance.Data {
		res = append(res, v)
	}
	return res, nil
}

func (sdb *SmartDb) GetOne(domainPath string, id string) (map[string]interface{}, error) {
	var smartInstance models.SmartInstance
	err := sdb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(smartBucketBytes)
		v := b.Get([]byte(sdb.toKey(domainPath)))
		if v == nil {
			return nil
		}
		return utils.Deserialize(v, &smartInstance)
	})
	if err != nil {
		logger.Error("error on getting value from BoltDB for key: "+domainPath, err)
		return nil, err
	}
	return smartInstance.Data[id], nil
}

func (sdb *SmartDb) InsertOne(domainPath string, reqBody map[string]interface{}) (string, error) {
	id := uuid.New().String()
	reqBody[proteusExternalSmartIdKey] = id

	var smartInstance models.SmartInstance
	err := sdb.db.Update(func(tx *bolt.Tx) error {
		key := []byte(sdb.toKey(domainPath))

		b := tx.Bucket(smartBucketBytes)
		v := b.Get(key)
		if v == nil {
			smartInstance = models.SmartInstance{
				Data: make(map[string]map[string]interface{}),
			}
		} else {
			err := utils.Deserialize(v, &smartInstance)
			if err != nil {
				logger.Error("error on deserializing BoltDB value for key: "+domainPath, err)
				return err
			}
		}
		smartInstance.Data[id] = reqBody

		serialized, err := utils.Serialize(smartInstance)
		if err != nil {
			logger.Error("error on serializing Smart instance: "+domainPath, err)
			return err
		}
		return b.Put(key, serialized)
	})
	if err != nil {
		logger.Error("error on inserting value to BoltDB for key: "+domainPath, err)
		return "", err
	}
	return id, nil
}

func (sdb *SmartDb) UpdateOne(domainPath string, id string, reqBody map[string]interface{}) (found bool, err error) {
	found = true

	var smartInstance models.SmartInstance
	err = sdb.db.Update(func(tx *bolt.Tx) error {
		key := []byte(sdb.toKey(domainPath))

		b := tx.Bucket(smartBucketBytes)
		v := b.Get(key)
		if v == nil {
			found = false
			return nil
		}
		err = utils.Deserialize(v, &smartInstance)
		if err != nil {
			logger.Error("error on deserializing BoltDB value for key: "+domainPath, err)
			return err
		}
		if _, ok := smartInstance.Data[id]; ok {
			reqBody[proteusExternalSmartIdKey] = id
			smartInstance.Data[id] = reqBody
		}

		serialized, err := utils.Serialize(smartInstance)
		if err != nil {
			logger.Error("error on serializing Smart instance: "+domainPath, err)
			return err
		}
		return b.Put(key, serialized)
	})
	if err != nil {
		logger.Error("error on updating value in BoltDB for key: "+domainPath, err)
		return false, err
	}
	return found, nil
}

func (sdb *SmartDb) DeleteOne(domainPath string, id string) (found bool, err error) {
	found = true

	var smartInstance models.SmartInstance
	err = sdb.db.Update(func(tx *bolt.Tx) error {
		key := []byte(sdb.toKey(domainPath))

		b := tx.Bucket(smartBucketBytes)
		v := b.Get(key)
		if v == nil {
			found = false
			return nil
		}
		err = utils.Deserialize(v, &smartInstance)
		if err != nil {
			logger.Error("error on deserializing BoltDB value for key: "+domainPath, err)
			return err
		}
		if _, ok := smartInstance.Data[id]; ok {
			delete(smartInstance.Data, id)
		} else {
			found = false
			return nil
		}

		serialized, err := utils.Serialize(smartInstance)
		if err != nil {
			logger.Error("error on serializing Smart instance: "+domainPath, err)
			return err
		}
		return b.Put(key, serialized)
	})
	if err != nil {
		logger.Error("error on deleting value from BoltDB for key: "+domainPath, err)
		return false, err
	}
	return found, nil
}

func (sdb *SmartDb) Delete(domainPath string) (found bool, err error) {
	found = true

	err = sdb.db.Update(func(tx *bolt.Tx) error {
		key := []byte(sdb.toKey(domainPath))

		b := tx.Bucket(smartBucketBytes)
		v := b.Get(key)
		if v == nil {
			found = false
			return nil
		}
		return b.Delete(key)
	})
	if err != nil {
		logger.Error("error on deleting value from BoltDB for key: "+domainPath, err)
		return false, err
	}
	return found, nil
}

func (sdb *SmartDb) Clear() error {
	err := sdb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(smartBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			return b.Delete(k)
		})
	})

	if err != nil {
		logger.Error("error on deleting all Smart endpoints", err)
		return err
	}
	return nil
}

func (sdb *SmartDb) toKey(domainPath string) string {
	return domainPath
}
