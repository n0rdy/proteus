package utils

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"
)

var redirectCodes = map[int]bool{
	301: true,
	302: true,
	303: true,
	307: true,
	308: true,
}

func RequireRedirect(statusCode int) bool {
	return redirectCodes[statusCode]
}

func RequestBodyAsBytes(reqBody io.ReadCloser) ([]byte, error) {
	if reqBody == nil {
		return []byte{}, nil
	}
	return io.ReadAll(reqBody)
}

func RequestBodyAsMap(reqBody io.ReadCloser, contentType string) (map[string]interface{}, error) {
	if reqBody == nil {
		return map[string]interface{}{}, nil
	}

	reqBodyAsBytes, err := RequestBodyAsBytes(reqBody)
	if err != nil {
		return nil, err
	}

	var respBodyAsMap map[string]interface{}
	switch SanitizeContentType(contentType) {
	case "application/json":
		err = json.Unmarshal(reqBodyAsBytes, &respBodyAsMap)
		if err != nil {
			return nil, err
		}
	case "application/xml":
		err = xml.Unmarshal(reqBodyAsBytes, &respBodyAsMap)
		if err != nil {
			return nil, err
		}
	}
	return respBodyAsMap, nil
}

func GetAcceptHeaderMediaTypes(acceptHeader string) map[string]bool {
	mediaTypes := strings.Split(acceptHeader, ",")
	mtMap := make(map[string]bool)
	for _, mediaType := range mediaTypes {
		mtMap[SanitizeContentType(mediaType)] = true
	}
	return mtMap
}

func GetAcceptHeaderMediaTypesInOrder(acceptHeader string) []string {
	mediaTypes := strings.Split(acceptHeader, ",")
	for i, mediaType := range mediaTypes {
		mediaTypes[i] = SanitizeContentType(mediaType)
	}
	return mediaTypes
}

func SanitizeContentType(contentType string) string {
	return strings.ToLower(strings.Split(contentType, ";")[0])
}

func CloseSafe(closer io.Closer) {
	if closer != nil {
		closer.Close()
	}
}
