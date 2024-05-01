package db

import (
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/utils"
	"github.com/n0rdy/proteus/logger"
	commonUtils "github.com/n0rdy/proteus/utils"
	bolt "go.etcd.io/bbolt"
	"strings"
)

const (
	restBucket = "REST"
)

var restBucketBytes = []byte(restBucket)

type EndpointsDb struct {
	db *bolt.DB
}

func NewEndpointsDb() (*EndpointsDb, error) {
	boltDb, err := bolt.Open(commonUtils.GetOsSpecificDbDir()+"proteus_endpoints.db", 0600, nil)
	if err != nil {
		return nil, err
	}

	err = boltDb.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists(restBucketBytes)
		if err != nil {
			logger.Error("error on creating BoltDB bucket: "+restBucket, err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &EndpointsDb{db: boltDb}, nil
}

func (edb *EndpointsDb) Close() error {
	return edb.db.Close()
}

func (edb *EndpointsDb) GetAllRest() ([]models.RestEndpoint, error) {
	var res []models.RestEndpoint
	err := edb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(restBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			var endpoint models.RestEndpoint
			err := utils.Deserialize(v, &endpoint)
			if err != nil {
				logger.Error("error on deserializing BoltDB value for key: "+string(k), err)
				return err
			}
			res = append(res, endpoint)
			return nil
		})
	})

	if err != nil {
		logger.Error("error on getting BoltDB values for bucket: "+restBucket, err)
		return nil, err
	}
	if res == nil {
		return []models.RestEndpoint{}, nil
	}

	return res, nil
}

func (edb *EndpointsDb) GetOneRest(method string, path string) (*models.RestEndpoint, error) {
	var res models.RestEndpoint
	err := edb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(restBucketBytes)
		v := b.Get([]byte(edb.toKey(method, path)))
		if v == nil {
			return nil
		}
		return utils.Deserialize(v, &res)
	})

	if err != nil {
		logger.Error("error on getting BoltDB value for key: "+edb.toKey(method, path), err)
		return nil, err
	}
	if res.Path == "" {
		return nil, nil
	}
	return &res, nil
}

func (edb *EndpointsDb) InsertOneRest(endpoint models.RestEndpoint) error {
	serialized, err := utils.Serialize(endpoint)
	if err != nil {
		logger.Error("error on serializing REST endpoint: "+endpoint.Path, err)
		return err
	}

	err = edb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(restBucketBytes)
		return b.Put([]byte(edb.toKey(endpoint.Method, endpoint.Path)), serialized)
	})
	if err != nil {
		logger.Error("error on inserting REST endpoint: "+endpoint.Path, err)
		return err
	}
	return nil
}

func (edb *EndpointsDb) DeleteAllRest() error {
	err := edb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(restBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			return b.Delete(k)
		})
	})

	if err != nil {
		logger.Error("error on deleting all REST endpoints", err)
		return err
	}
	return nil
}

func (edb *EndpointsDb) DeleteOneRest(method string, path string) error {
	err := edb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(restBucketBytes)
		return b.Delete([]byte(edb.toKey(method, path)))
	})

	if err != nil {
		logger.Error("error on deleting REST endpoint: "+edb.toKey(method, path), err)
		return err
	}
	return nil
}

func (edb *EndpointsDb) toKey(method string, path string) string {
	return strings.ToLower(method + "_" + path)
}
