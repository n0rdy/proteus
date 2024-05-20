package models

import (
	"bytes"
	"encoding/gob"
)

func init() {
	gob.Register(RestEndpoint{})
	gob.Register(SmartInstance{})
	// to support smart endpoints
	gob.Register([]interface{}{})
	gob.Register(map[string]interface{}{})
}

func Serialize[T RestEndpoint | SmartInstance](obj T) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Deserialize[T RestEndpoint | SmartInstance](data []byte, obj *T) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	err := dec.Decode(obj)
	if err != nil {
		return err
	}
	return nil
}
