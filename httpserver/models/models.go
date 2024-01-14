package models

import (
	"regexp"
	"time"
)

// requests models:

type RestEndpoint struct {
	Path                      string                                   `json:"path,omitempty"`
	Method                    string                                   `json:"method,omitempty"`
	Description               string                                   `json:"description,omitempty"`
	DefaultResponseStatusCode int                                      `json:"defaultResponseStatusCode,omitempty"`
	Responses                 map[string]RestEndpointResponseStructure `json:"responses,omitempty"`
}

type RestEndpointResponseStructure struct {
	Body    *RestEndpointResponseBody `json:"body,omitempty"`
	Headers []RestEndpointHeader      `json:"headers,omitempty"`
	Cookies []RestEndpointCookie      `json:"cookies,omitempty"`
}

type RestEndpointResponseBody struct {
	AsString string `json:"asString,omitempty"`
	AsBase64 string `json:"asBase64,omitempty"`
}

type RestEndpointHeader struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values,omitempty"`
}

type RestEndpointCookie struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type BasicAuthCredentialsInstance struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type ApiKeyAuthCredentialsInstance struct {
	KeyName  string `json:"keyName,omitempty"`
	KeyValue string `json:"keyValue,omitempty"`
}

// responses models:

type DefaultResponse struct {
	Message string `json:"message,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

type ProtectedResourceResponse struct {
	Message string `json:"message,omitempty"`
}

type SmartCreatedResponse struct {
	Id string `json:"id,omitempty"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

type EndpointResponse struct {
	Path        string                                   `json:"path,omitempty"`
	Method      string                                   `json:"method,omitempty"`
	Description string                                   `json:"description,omitempty"`
	Responses   map[string]RestEndpointResponseStructure `json:"responses,omitempty"`
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
