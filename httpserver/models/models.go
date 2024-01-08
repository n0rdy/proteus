package models

import "time"

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

type ResponseHints struct {
	StatusCode       int
	Body             []byte
	ContentType      string
	RedirectLocation string
	Wait             time.Duration
}
