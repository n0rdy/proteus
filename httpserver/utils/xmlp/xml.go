package xmlp

import (
	"encoding/xml"
	"github.com/clbanning/mxj/v2"
)

func Marshal(payload interface{}) ([]byte, error) {
	var respBody []byte
	var err error

	// default Go XML marshaling doesn't support `map` data type, that's why we need to fullback to MXJ library for such cases
	switch payloadCasted := payload.(type) {
	case map[string]interface{}:
		payloadAsMxj := mxj.Map(payloadCasted)
		respBody, err = payloadAsMxj.Xml()
	case []map[string]interface{}:
		payloadAsMxj := mxj.Maps{}
		for _, item := range payloadCasted {
			payloadAsMxj = append(payloadAsMxj, item)
		}
		var respBodyAsString string
		respBodyAsString, err = payloadAsMxj.XmlString()
		if err == nil && respBodyAsString != "" {
			respBody = []byte(respBodyAsString)
		}
	default:
		respBody, err = xml.Marshal(payload)
	}

	return respBody, err
}
