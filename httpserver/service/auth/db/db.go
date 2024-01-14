package db

import (
	"github.com/n0rdy/proteus/httpserver/logger"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/utils"
	bolt "go.etcd.io/bbolt"
)

const (
	basicAuthBucket  = "basic"
	apiKeyAuthBucket = "apikey"
)

var basicAuthBucketBytes = []byte(basicAuthBucket)
var apiKeyAuthBucketBytes = []byte(apiKeyAuthBucket)

type AuthDb struct {
	db *bolt.DB
}

func NewAuthDb() (*AuthDb, error) {
	boltDb, err := bolt.Open(utils.GetOsSpeificDbDir()+"proteus_auth.db", 0600, nil)
	if err != nil {
		return nil, err
	}

	err = boltDb.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists(basicAuthBucketBytes)
		if err != nil {
			logger.Error("error on creating BoltDB bucket: "+basicAuthBucket, err)
			return err
		}

		_, err = tx.CreateBucketIfNotExists(apiKeyAuthBucketBytes)
		if err != nil {
			logger.Error("error on creating BoltDB bucket: "+apiKeyAuthBucket, err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &AuthDb{db: boltDb}, nil
}

func (adb *AuthDb) Close() error {
	return adb.db.Close()
}

func (adb *AuthDb) GetOneBasicAuth(username string) *models.BasicAuthCredentialsInstance {
	var password string
	adb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(basicAuthBucketBytes)
		v := b.Get([]byte(username))
		if v == nil {
			return nil
		}
		password = string(v)
		return nil
	})
	if password == "" {
		return nil
	}
	return &models.BasicAuthCredentialsInstance{
		Username: username,
		Password: password,
	}
}

func (adb *AuthDb) GetOneApiKeyAuth(apiKeyName string) *models.ApiKeyAuthCredentialsInstance {
	var value string
	adb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeyAuthBucketBytes)
		v := b.Get([]byte(apiKeyName))
		if v == nil {
			return nil
		}
		value = string(v)
		return nil
	})
	if value == "" {
		return nil
	}
	return &models.ApiKeyAuthCredentialsInstance{
		KeyName:  apiKeyName,
		KeyValue: value,
	}
}

func (adb *AuthDb) GetAllBasicAuth() []models.BasicAuthCredentialsInstance {
	basicAuthCredentialsInstances := make([]models.BasicAuthCredentialsInstance, 0)
	adb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(basicAuthBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			basicAuthCredentialsInstances = append(basicAuthCredentialsInstances, models.BasicAuthCredentialsInstance{
				Username: string(k),
				Password: string(v),
			})
			return nil
		})
	})
	return basicAuthCredentialsInstances
}

func (adb *AuthDb) GetAllApiKeyAuth() []models.ApiKeyAuthCredentialsInstance {
	apiKeyAuthCredentialsInstances := make([]models.ApiKeyAuthCredentialsInstance, 0)
	adb.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeyAuthBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			apiKeyAuthCredentialsInstances = append(apiKeyAuthCredentialsInstances, models.ApiKeyAuthCredentialsInstance{
				KeyName:  string(k),
				KeyValue: string(v),
			})
			return nil
		})
	})
	return apiKeyAuthCredentialsInstances
}

func (adb *AuthDb) InsertBasicAuth(creds models.BasicAuthCredentialsInstance) error {
	return adb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(basicAuthBucketBytes)
		err := b.Put([]byte(creds.Username), []byte(creds.Password))
		if err != nil {
			logger.Error("error on putting data into BoltDB bucket: "+basicAuthBucket, err)
			return err
		}
		return nil
	})
}

func (adb *AuthDb) InsertApiKeyAuth(creds models.ApiKeyAuthCredentialsInstance) error {
	return adb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeyAuthBucketBytes)
		err := b.Put([]byte(creds.KeyName), []byte(creds.KeyValue))
		if err != nil {
			logger.Error("error on putting data into BoltDB bucket: "+apiKeyAuthBucket, err)
			return err
		}
		return nil
	})
}

func (adb *AuthDb) DeleteOneBasicAuth(username string) error {
	return adb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(basicAuthBucketBytes)
		return b.Delete([]byte(username))
	})
}

func (adb *AuthDb) DeleteOneApiKeyAuth(apiKeyName string) error {
	return adb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeyAuthBucketBytes)
		return b.Delete([]byte(apiKeyName))
	})
}

func (adb *AuthDb) DeleteAllBasicAuth() error {
	return adb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(basicAuthBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			return b.Delete(k)
		})
	})
}

func (adb *AuthDb) DeleteAllApiKeyAuth() error {
	return adb.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(apiKeyAuthBucketBytes)
		return b.ForEach(func(k, v []byte) error {
			return b.Delete(k)
		})
	})
}
