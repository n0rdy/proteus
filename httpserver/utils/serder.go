package utils

import (
	"bytes"
	"encoding/gob"
	"github.com/n0rdy/proteus/httpserver/models"
)

func init() {
	gob.Register(models.RestEndpoint{})
}

func Serialize[T models.RestEndpoint](obj T) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Deserialize[T models.RestEndpoint](data []byte, obj *T) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	err := dec.Decode(obj)
	if err != nil {
		return err
	}
	return nil
}
