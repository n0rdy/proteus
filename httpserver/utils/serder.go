package utils

import (
	"bytes"
	"encoding/gob"
	"github.com/n0rdy/proteus/httpserver/models"
)

func init() {
	gob.Register(models.RestEndpoint{})
	gob.Register(models.SmartInstance{})
	// to support smart endpoints
	gob.Register([]interface{}{})
	gob.Register(map[string]interface{}{})
}

func Serialize[T models.RestEndpoint | models.SmartInstance](obj T) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Deserialize[T models.RestEndpoint | models.SmartInstance](data []byte, obj *T) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	err := dec.Decode(obj)
	if err != nil {
		return err
	}
	return nil
}
