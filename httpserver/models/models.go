package models

import "time"

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

// responses models:

type DefaultResponse struct {
	Message string `json:"message,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
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

type ResponseHints struct {
	StatusCode       int
	Body             []byte
	ContentType      string
	RedirectLocation string
	Wait             time.Duration
}
