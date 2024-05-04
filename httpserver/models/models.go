package models

import (
	"regexp"
	"time"
)

// requests models:

type RestEndpoint struct {
	Path                      string                                   `json:"path,omitempty" xml:"path,omitempty"`
	Method                    string                                   `json:"method,omitempty" xml:"method,omitempty"`
	Description               string                                   `json:"description,omitempty" xml:"description,omitempty"`
	DefaultResponseStatusCode int                                      `json:"defaultResponseStatusCode,omitempty" xml:"defaultResponseStatusCode,omitempty"`
	Responses                 map[string]RestEndpointResponseStructure `json:"responses,omitempty" xml:"responses,omitempty"`
}

type RestEndpointResponseStructure struct {
	Body    *RestEndpointResponseBody `json:"body,omitempty" xml:"body,omitempty"`
	Headers []RestEndpointHeader      `json:"headers,omitempty" xml:"headers,omitempty"`
	Cookies []RestEndpointCookie      `json:"cookies,omitempty" xml:"cookies,omitempty"`
}

type RestEndpointResponseBody struct {
	AsString string `json:"asString,omitempty" xml:"asString,omitempty"`
	AsBase64 string `json:"asBase64,omitempty" xml:"asBase64,omitempty"`
}

type RestEndpointHeader struct {
	Name   string   `json:"name,omitempty" xml:"name,omitempty"`
	Values []string `json:"values,omitempty" xml:"values,omitempty"`
}

type RestEndpointCookie struct {
	Name  string `json:"name,omitempty" xml:"name,omitempty"`
	Value string `json:"value,omitempty" xml:"value,omitempty"`
}

type BasicAuthCredentialsInstance struct {
	Username string `json:"username,omitempty" xml:"username,omitempty"`
	Password string `json:"password,omitempty" xml:"password,omitempty"`
}

type ApiKeyAuthCredentialsInstance struct {
	KeyName  string `json:"keyName,omitempty" xml:"keyName,omitempty"`
	KeyValue string `json:"keyValue,omitempty" xml:"keyValue,omitempty"`
}

// responses models:

type DefaultResponse struct {
	Message string `json:"message,omitempty" xml:"message,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message,omitempty" xml:"message,omitempty"`
	Code    string `json:"code,omitempty" xml:"code,omitempty"`
}

type ProtectedResourceResponse struct {
	Message string `json:"message,omitempty" xml:"message,omitempty"`
}

type SmartCreatedResponse struct {
	Id string `json:"id,omitempty" xml:"id,omitempty"`
}

type HealthResponse struct {
	Status string `json:"status" xml:"status"`
}

type EndpointResponse struct {
	Path        string                                   `json:"path,omitempty" xml:"path,omitempty"`
	Method      string                                   `json:"method,omitempty" xml:"method,omitempty"`
	Description string                                   `json:"description,omitempty" xml:"description,omitempty"`
	Responses   map[string]RestEndpointResponseStructure `json:"responses,omitempty" xml:"responses,omitempty"`
}

// other models:

type SmartInstance struct {
	Data map[string]map[string]interface{}
}

type ProteusHints struct {
	StatusCode       int
	Body             []byte
	ContentType      string
	RedirectLocation string
	Wait             time.Duration
	ApiKey           *ProteusHintsApiKeyAuth
}

type ProteusHintsApiKeyAuth struct {
	KeyName string
	// accepts values: "header", "query". Header is default.
	Location string
	// accepts values: "plain", "base64". Plain is default.
	ValueFormat string
	// used if the key value goes with some prefix, e.g. "ApiKey "
	ValueParserRegexp *regexp.Regexp
}
