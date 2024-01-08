package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/n0rdy/proteus/httpserver/common"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/hints"
	"github.com/n0rdy/proteus/httpserver/service/logger"
	"github.com/n0rdy/proteus/httpserver/service/smart"
	"github.com/n0rdy/proteus/httpserver/utils"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ProteusRouter struct {
	shutdownCh   chan struct{}
	restartCh    chan struct{}
	hintsParser  *hints.ResponseHintsParser
	smartService *smart.SmartService
	logger       logger.Logger
}

func NewProteusRouter(logger logger.Logger, shutdownCh chan struct{}, restartCh chan struct{}) ProteusRouter {
	return ProteusRouter{
		shutdownCh:   shutdownCh,
		restartCh:    restartCh,
		hintsParser:  &hints.ResponseHintsParser{},
		smartService: smart.NewSmartService(),
		logger:       logger,
	}
}

func (pr *ProteusRouter) NewRouter() *chi.Mux {
	router := chi.NewRouter()

	router.Route("/api/v1/proteus", func(r chi.Router) {
		r.Route("/http/statuses", func(r chi.Router) {
			r.HandleFunc("/{status}", pr.handleStatuses)
		})

		r.Route("/smart", func(r chi.Router) {
			r.HandleFunc("/*", pr.handleSmart)
		})

		r.Route("/admin", func(r chi.Router) {
			r.Route("/http/endpoints", func(r chi.Router) {
				r.Get("/", pr.getEndpoints)
				r.Post("/", pr.addEndpoint)
				r.Delete("/", pr.deleteAllCustomEndpoints)
				r.Put("/{endpointPath}", pr.changeEndpoint)
				r.Delete("/{endpointPath}", pr.deleteEndpoint)
			})

			r.Put("/restart", pr.restart)
			r.Delete("/shutdown", pr.shutdown)
		})

		r.HandleFunc("/mirror", pr.mirrorRequest)
	})

	// TODO: fetch from DB and add custom endpoints
	// TODO: add HTML page with admin UI

	router.Get("/healthcheck", pr.healthCheck)

	router.HandleFunc("/*", pr.handleAnyReq)

	return router
}

func (pr *ProteusRouter) handleStatuses(w http.ResponseWriter, req *http.Request) {
	statusCode, err := pr.getStatusCode(req)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidStatusCode)
		return
	}

	responseHints := pr.hintsParser.ParseResponseHints(req)
	if responseHints == nil {
		respBody := forStatusCode(statusCode)
		pr.enrichResponse(w, statusCode)
		pr.sendJsonResponse(w, statusCode, respBody)
	} else {
		// status code is ignored from hints, as the purpose of this endpoint is to return the status code from the URL
		responseHints.StatusCode = statusCode
		pr.sendResponseFromHints(w, responseHints)
	}
}

func (pr *ProteusRouter) handleSmart(w http.ResponseWriter, req *http.Request) {
	reqPath := req.URL.Path
	domainPath, found := strings.CutPrefix(reqPath, common.SmartEndpointPath)
	if !found {
		domainPath, found = strings.CutPrefix(reqPath, common.SmartEndpointPathWithoutLeadingSlash)
		if !found {
			// this should never happen
			pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
			return
		}
	}

	if domainPath == "" || domainPath == "/" {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorInvalidSmartRequestPath, reqPath), common.ErrorCodeInvalidSmartRequestPath)
		return
	}

	var reqBodyAsMap map[string]interface{}
	if req.Body != nil {
		defer req.Body.Close()
		var err error
		reqBodyAsMap, err = utils.RequestBodyAsMap(req.Body, req.Header.Get("Content-Type"))
		if err != nil {
			pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
			return
		}
	}

	switch req.Method {
	case http.MethodGet:
		pr.handleSmartGetRequest(w, domainPath)
	case http.MethodPost:
		pr.handleSmartCreateRequest(w, domainPath, reqBodyAsMap)
	case http.MethodPut:
		pr.handleSmartUpdateRequest(w, domainPath, reqBodyAsMap)
	case http.MethodDelete:
		pr.handleSmartDeleteRequest(w, domainPath)
	default:
		pr.sendJsonErrorResponse(w, http.StatusMethodNotAllowed, fmt.Sprintf(common.ErrorInvalidSmartRequestMethod, req.Method), common.ErrorCodeInvalidSmartRequestMethod)
	}
}

func (pr *ProteusRouter) getEndpoints(w http.ResponseWriter, req *http.Request) {
	// TODO: implement
	w.WriteHeader(http.StatusNotImplemented)
}

func (pr *ProteusRouter) addEndpoint(w http.ResponseWriter, req *http.Request) {
	// TODO: implement
	w.WriteHeader(http.StatusNotImplemented)
}

func (pr *ProteusRouter) deleteAllCustomEndpoints(w http.ResponseWriter, req *http.Request) {
	// TODO: implement
	w.WriteHeader(http.StatusNotImplemented)
}

func (pr *ProteusRouter) changeEndpoint(w http.ResponseWriter, req *http.Request) {
	// TODO: implement
	w.WriteHeader(http.StatusNotImplemented)
}

func (pr *ProteusRouter) deleteEndpoint(w http.ResponseWriter, req *http.Request) {
	// TODO: implement
	w.WriteHeader(http.StatusNotImplemented)
}

func (pr *ProteusRouter) healthCheck(w http.ResponseWriter, req *http.Request) {
	pr.sendJsonResponse(w, http.StatusOK, healthOk)
}

func (pr *ProteusRouter) shutdown(w http.ResponseWriter, req *http.Request) {
	pr.shutdownCh <- struct{}{}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) restart(w http.ResponseWriter, req *http.Request) {
	pr.restartCh <- struct{}{}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) mirrorRequest(w http.ResponseWriter, req *http.Request) {
	respBodyAsBytes, err := utils.RequestBodyAsBytes(req.Body)
	defer utils.CloseSafe(req.Body)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
		return
	}

	respHeaders := make(map[string][]string)
	for key, values := range req.Header {
		respHeaders[key] = values
	}

	pr.sendMirrorResponse(w, respBodyAsBytes, respHeaders, req.Cookies())
}

func (pr *ProteusRouter) handleAnyReq(w http.ResponseWriter, req *http.Request) {
	responseHints := pr.hintsParser.ParseResponseHints(req)
	if responseHints == nil {
		pr.sendJsonResponse(w, http.StatusOK, _200OkResponse)
	} else {
		pr.sendResponseFromHints(w, responseHints)
	}
}

func (pr *ProteusRouter) getStatusCode(req *http.Request) (int, error) {
	statusCode := chi.URLParam(req, "status")
	if statusCode == "" {
		return 0, errors.New(fmt.Sprintf(common.ErrorInvalidStatusCode, statusCode))
	}

	statusCodeAsInt, err := strconv.Atoi(statusCode)
	if err != nil {
		return 0, errors.New(fmt.Sprintf(common.ErrorInvalidStatusCode, statusCode))
	}
	if statusCodeAsInt < 100 || statusCodeAsInt > 599 {
		return 0, errors.New(fmt.Sprintf(common.ErrorInvalidStatusCode, statusCode))
	}
	return statusCodeAsInt, nil
}

func (pr *ProteusRouter) handleSmartGetRequest(w http.ResponseWriter, domainPath string) {
	respBody, withId := pr.smartService.Get(domainPath)
	if respBody == nil {
		// `withId` means that all the entities are requested, thus, if nothing is found, we return an empty array
		// if `withId` is false, then we return 404, as the requested entity is not found
		if withId {
			pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundSmartPath, domainPath), common.ErrorCodeNotFoundSmartPath)
			return
		} else {
			respBody = []interface{}{}
		}
	}
	pr.sendJsonResponse(w, http.StatusOK, respBody)
}

func (pr *ProteusRouter) handleSmartCreateRequest(w http.ResponseWriter, domainPath string, reqBodyAsMap map[string]interface{}) {
	if reqBodyAsMap == nil || len(reqBodyAsMap) == 0 {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
		return
	}

	id := pr.smartService.Create(domainPath, reqBodyAsMap)
	pr.sendJsonResponse(w, http.StatusCreated, models.SmartCreatedResponse{Id: string(id)})
}

func (pr *ProteusRouter) handleSmartUpdateRequest(w http.ResponseWriter, domainPath string, reqBodyAsMap map[string]interface{}) {
	if reqBodyAsMap == nil || len(reqBodyAsMap) == 0 {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
		return
	}

	found := pr.smartService.Update(domainPath, reqBodyAsMap)
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundSmartPath, domainPath), common.ErrorCodeNotFoundSmartPath)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) handleSmartDeleteRequest(w http.ResponseWriter, domainPath string) {
	found := pr.smartService.Delete(domainPath)
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundSmartPath, domainPath), common.ErrorCodeNotFoundSmartPath)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) enrichResponse(w http.ResponseWriter, statusCode int) {
	if utils.RequireRedirect(statusCode) {
		w.Header().Set("Location", "https://www.example.com")
	}
}

func (pr *ProteusRouter) sendMirrorResponse(w http.ResponseWriter, respBody []byte, respHeaders map[string][]string, respCookies []*http.Cookie) {
	for key, values := range respHeaders {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	for _, cookie := range respCookies {
		http.SetCookie(w, cookie)
	}

	w.WriteHeader(http.StatusOK)
	if len(respBody) != 0 {
		w.Write(respBody)
	}
}

func (pr *ProteusRouter) sendNoContentResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func (pr *ProteusRouter) sendJsonResponse(w http.ResponseWriter, httpCode int, payload interface{}) {
	respBody, err := json.Marshal(payload)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorResponseMarshalling, common.ErrorCodeResponseMarshalling)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	w.Write(respBody)
}

func (pr *ProteusRouter) sendResponseFromHints(w http.ResponseWriter, hints *models.ResponseHints) {
	if hints.Wait > 0 {
		time.Sleep(hints.Wait)
	}

	if hints.ContentType != "" {
		w.Header().Set("Content-Type", hints.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}

	statusCode := hints.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	w.WriteHeader(statusCode)

	if utils.RequireRedirect(statusCode) {
		if hints.RedirectLocation != "" {
			w.Header().Set("Location", hints.RedirectLocation)
		} else {
			w.Header().Set("Location", "https://www.example.com")
		}
	}

	if len(hints.Body) > 0 {
		w.Write(hints.Body)
	} else {
		respBody := forStatusCode(statusCode)
		respBodyAsBytes, _ := json.Marshal(respBody)
		w.Write(respBodyAsBytes)
	}
}

func (pr *ProteusRouter) sendJsonErrorResponse(w http.ResponseWriter, httpCode int, message string, errorCode string) {
	pr.sendJsonResponse(w, httpCode, models.ErrorResponse{Message: message, Code: errorCode})
}
