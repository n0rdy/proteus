package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/n0rdy/proteus/httpserver/common"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/auth/apikey"
	"github.com/n0rdy/proteus/httpserver/service/auth/basic"
	"github.com/n0rdy/proteus/httpserver/service/endpoints"
	"github.com/n0rdy/proteus/httpserver/service/hints"
	"github.com/n0rdy/proteus/httpserver/service/smart"
	"github.com/n0rdy/proteus/httpserver/utils"
	"github.com/n0rdy/proteus/logger"
	"github.com/rs/cors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ProteusRouter struct {
	shutdownCh        chan struct{}
	restartCh         chan struct{}
	hintsParser       *hints.ProteusHintsParser
	basicAuthService  *basic.Service
	apiKeyAuthService *apikey.Service
	smartService      *smart.Service
	endpointService   *endpoints.Service
}

func NewProteusRouter(
	basicAuthService *basic.Service,
	apiKeyAuthService *apikey.Service,
	smartService *smart.Service,
	endpointService *endpoints.Service,
	shutdownCh chan struct{},
	restartCh chan struct{},
) *ProteusRouter {
	return &ProteusRouter{
		shutdownCh:        shutdownCh,
		restartCh:         restartCh,
		hintsParser:       &hints.ProteusHintsParser{},
		basicAuthService:  basicAuthService,
		apiKeyAuthService: apiKeyAuthService,
		smartService:      smartService,
		endpointService:   endpointService,
	}
}

func (pr *ProteusRouter) NewRouter() *chi.Mux {
	router := chi.NewRouter()
	// TODO: consider adding CORS configs to tune the allowed origins, methods, etc.
	router.Use(cors.AllowAll().Handler)
	router.Use(Logger)

	// TODO: add HTML page with admin UI

	router.Route("/api/v1/proteus", func(r chi.Router) {
		r.Route("/http/statuses", func(r chi.Router) {
			r.HandleFunc("/{status}", pr.handleStatuses)
		})

		r.Route("/auth", func(r chi.Router) {
			r.Route("/basic", func(r chi.Router) {
				r.HandleFunc("/resource", pr.handleBasicAuthProtectedResourceReq)
				r.HandleFunc("/resource/*", pr.handleBasicAuthProtectedResourceReq)
			})

			r.Route("/apikey", func(r chi.Router) {
				r.HandleFunc("/resource", pr.handleApiKeyAuthProtectedResourceReq)
				r.HandleFunc("/resource/*", pr.handleApiKeyAuthProtectedResourceReq)
			})
		})

		r.Route("/smart", func(r chi.Router) {
			r.Delete("/", pr.clearSmart)

			r.HandleFunc("/*", pr.handleSmart)
		})

		r.Route("/admin", func(r chi.Router) {
			r.Route("/rest/endpoints", func(r chi.Router) {
				r.Get("/", pr.getRestEndpoints)
				r.Post("/", pr.addRestEndpoint)
				r.Delete("/", pr.deleteAllRestEndpoints)
				r.Get("/{method}/*", pr.getRestEndpoint)
				r.Put("/{method}/*", pr.changeRestEndpoint)
				r.Delete("/{method}/*", pr.deleteRestEndpoint)
			})

			r.Route("/auth/credentials/", func(r chi.Router) {
				r.Route("/basic", func(r chi.Router) {
					r.Get("/", pr.getAllBasicAuthCreds)
					r.Post("/", pr.addBasicAuthCreds)
					r.Delete("/", pr.deleteAllBasicAuthCreds)
					r.Delete("/{username}", pr.deleteBasicAuthCreds)
				})

				r.Route("/apikey", func(r chi.Router) {
					r.Get("/", pr.getAllApiKeyAuthCreds)
					r.Post("/", pr.addApiKeyAuthCreds)
					r.Delete("/", pr.deleteAllApiKeyAuthCreds)
					r.Delete("/{keyName}", pr.deleteApiKeyAuthCreds)
				})
			})

			r.Put("/restart", pr.restart)
			r.Delete("/shutdown", pr.shutdown)
		})

		r.HandleFunc("/mirror", pr.mirrorRequest)
	})

	pr.registerCustomRestEndpoints(router)

	router.Get("/healthcheck", pr.healthCheck)

	router.HandleFunc("/*", pr.handleAnyReq)

	return router
}

func (pr *ProteusRouter) handleBasicAuthProtectedResourceReq(w http.ResponseWriter, req *http.Request) {
	basicAuthHeader := req.Header.Get("Authorization")
	if basicAuthHeader == "" {
		pr.sendUnauthorizedResponse(w)
		return
	}

	if !pr.basicAuthService.CheckCredentials(basicAuthHeader) {
		pr.sendUnauthorizedResponse(w)
		return
	}

	proteusHints := pr.hintsParser.ParseHints(req)
	if proteusHints == nil {
		pr.sendJsonResponse(w, http.StatusOK, models.ProtectedResourceResponse{Message: "Welcome: you are in"})
	} else {
		pr.sendResponseFromHints(w, proteusHints)
	}
}

func (pr *ProteusRouter) handleApiKeyAuthProtectedResourceReq(w http.ResponseWriter, req *http.Request) {
	proteusHints := pr.hintsParser.ParseHints(req)
	if proteusHints == nil || proteusHints.ApiKey == nil {
		logger.Error("handleApiKeyAuthProtectedResourceReq: no hints provided, that's why there is no way to fetch the API key")
		pr.sendUnauthorizedResponse(w)
		return
	}

	apiKeyCreds := pr.parseApiKeyCreds(req, *proteusHints)
	if apiKeyCreds == nil {
		pr.sendUnauthorizedResponse(w)
		return
	}

	if !pr.apiKeyAuthService.CheckCredentials(*apiKeyCreds) {
		pr.sendUnauthorizedResponse(w)
		return
	}

	if proteusHints.StatusCode == 0 && proteusHints.Body == nil {
		pr.sendJsonResponse(w, http.StatusOK, models.ProtectedResourceResponse{Message: "Welcome: you are in"})
	} else {
		pr.sendResponseFromHints(w, proteusHints)
	}
}

func (pr *ProteusRouter) handleStatuses(w http.ResponseWriter, req *http.Request) {
	statusCode, err := pr.getStatusCode(req)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidStatusCode)
		return
	}

	proteusHints := pr.hintsParser.ParseHints(req)
	if proteusHints == nil {
		respBody := forStatusCode(statusCode)
		pr.enrichResponse(w, statusCode)
		pr.sendJsonResponse(w, statusCode, respBody)
	} else {
		// status code is ignored from hints, as the purpose of this endpoint is to return the status code from the URL
		proteusHints.StatusCode = statusCode
		pr.sendResponseFromHints(w, proteusHints)
	}
}

func (pr *ProteusRouter) clearSmart(w http.ResponseWriter, req *http.Request) {
	err := pr.smartService.Clear()
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	pr.sendNoContentResponse(w)
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

func (pr *ProteusRouter) getRestEndpoints(w http.ResponseWriter, req *http.Request) {
	restEndpoints, err := pr.endpointService.GetAllRestEndpoints()
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	pr.sendJsonResponse(w, http.StatusOK, restEndpoints)
}

func (pr *ProteusRouter) addRestEndpoint(w http.ResponseWriter, req *http.Request) {
	var restEndpoint models.RestEndpoint
	err := json.NewDecoder(req.Body).Decode(&restEndpoint)
	defer utils.CloseSafe(req.Body)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidRequestBody)
		return
	}

	err = pr.endpointService.AddRestEndpoint(restEndpoint)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidRequestBody)
		return
	}
	pr.sendNoContentResponse(w)

	pr.restartCh <- struct{}{}
}

func (pr *ProteusRouter) deleteAllRestEndpoints(w http.ResponseWriter, req *http.Request) {
	err := pr.endpointService.DeleteAllRestEndpoints()
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	pr.sendNoContentResponse(w)

	pr.restartCh <- struct{}{}
}

func (pr *ProteusRouter) getRestEndpoint(w http.ResponseWriter, req *http.Request) {
	method := chi.URLParam(req, "method")
	reqPath := req.URL.Path
	endpointPath, found := strings.CutPrefix(reqPath, common.RestEndpointPath+"/"+method)
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, common.ErrorNotFound, common.ErrorCodeNotFound)
		return
	}

	if method == "" || endpointPath == "" {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRestEndpointPath, common.ErrorCodeInvalidRestEndpointPath)
		return
	}

	restEndpoint, err := pr.endpointService.GetRestEndpoint(method, endpointPath)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	if restEndpoint == nil {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundRestEndpoint, method+endpointPath), common.ErrorCodeNotFoundRestEndpointPath)
		return
	}
	pr.sendJsonResponse(w, http.StatusOK, restEndpoint)
}

func (pr *ProteusRouter) changeRestEndpoint(w http.ResponseWriter, req *http.Request) {
	method := chi.URLParam(req, "method")
	reqPath := req.URL.Path
	endpointPath, found := strings.CutPrefix(reqPath, common.RestEndpointPath+"/"+method)
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, common.ErrorNotFound, common.ErrorCodeNotFound)
		return
	}

	var restEndpoint models.RestEndpoint
	err := json.NewDecoder(req.Body).Decode(&restEndpoint)
	defer utils.CloseSafe(req.Body)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidRequestBody)
		return
	}

	found, err = pr.endpointService.UpdateRestEndpoint(method, endpointPath, restEndpoint)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundRestEndpoint, method+endpointPath), common.ErrorCodeNotFoundRestEndpointPath)
		return
	}
	pr.sendNoContentResponse(w)

	pr.restartCh <- struct{}{}
}

func (pr *ProteusRouter) deleteRestEndpoint(w http.ResponseWriter, req *http.Request) {
	method := chi.URLParam(req, "method")
	reqPath := req.URL.Path
	endpointPath, found := strings.CutPrefix(reqPath, common.RestEndpointPath+"/"+method)
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, common.ErrorNotFound, common.ErrorCodeNotFound)
		return
	}

	found, err := pr.endpointService.DeleteRestEndpoint(method, endpointPath)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundRestEndpoint, method+endpointPath), common.ErrorCodeNotFoundRestEndpointPath)
		return
	}
	pr.sendNoContentResponse(w)

	pr.restartCh <- struct{}{}
}

func (pr *ProteusRouter) getAllBasicAuthCreds(w http.ResponseWriter, req *http.Request) {
	creds := pr.basicAuthService.GetAll()
	pr.sendJsonResponse(w, http.StatusOK, creds)
}

func (pr *ProteusRouter) addBasicAuthCreds(w http.ResponseWriter, req *http.Request) {
	var creds models.BasicAuthCredentialsInstance
	err := json.NewDecoder(req.Body).Decode(&creds)
	defer utils.CloseSafe(req.Body)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
		return
	}

	err = pr.basicAuthService.Add(creds)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidRequestBody)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) deleteAllBasicAuthCreds(w http.ResponseWriter, req *http.Request) {
	err := pr.basicAuthService.DeleteAll()
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) deleteBasicAuthCreds(w http.ResponseWriter, req *http.Request) {
	username := chi.URLParam(req, "username")
	found, err := pr.basicAuthService.Delete(username)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundBasicAuthCreds, username), common.ErrorCodeNotFoundBasicAuthCreds)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) getAllApiKeyAuthCreds(w http.ResponseWriter, req *http.Request) {
	creds := pr.apiKeyAuthService.GetAll()
	pr.sendJsonResponse(w, http.StatusOK, creds)
}

func (pr *ProteusRouter) addApiKeyAuthCreds(w http.ResponseWriter, req *http.Request) {
	var creds models.ApiKeyAuthCredentialsInstance
	err := json.NewDecoder(req.Body).Decode(&creds)
	defer utils.CloseSafe(req.Body)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
		return
	}

	err = pr.apiKeyAuthService.Add(creds)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, err.Error(), common.ErrorCodeInvalidRequestBody)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) deleteAllApiKeyAuthCreds(w http.ResponseWriter, req *http.Request) {
	err := pr.apiKeyAuthService.DeleteAll()
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) deleteApiKeyAuthCreds(w http.ResponseWriter, req *http.Request) {
	keyName := chi.URLParam(req, "keyName")
	found, err := pr.apiKeyAuthService.Delete(keyName)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundApiKeyAuthCreds, keyName), common.ErrorCodeNotFoundApiKeyAuthCreds)
		return
	}
	pr.sendNoContentResponse(w)
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

func (pr *ProteusRouter) registerCustomRestEndpoints(router *chi.Mux) {
	customRestEndpoints, err := pr.endpointService.GetAllRestEndpoints()
	if err != nil {
		logger.Error("registerCustomRestEndpoints: failed to get all custom rest endpoints", err)
		return
	}

	for _, restEndpoint := range customRestEndpoints {
		logger.Debug("Registering custom REST endpoint: " + restEndpoint.Method + " " + restEndpoint.Path)

		switch restEndpoint.Method {
		case http.MethodGet:
			router.Get(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		case http.MethodPost:
			router.Post(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		case http.MethodPut:
			router.Put(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		case http.MethodDelete:
			router.Delete(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		case http.MethodPatch:
			router.Patch(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		case http.MethodHead:
			router.Head(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		case http.MethodOptions:
			router.Options(restEndpoint.Path, pr.handleCustomRestEndpoint(restEndpoint))
		default:
			logger.Error("registerCustomRestEndpoints: invalid method: " + restEndpoint.Method)
		}
	}
}

func (pr *ProteusRouter) handleCustomRestEndpoint(endpoint models.RestEndpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		proteusHints := pr.hintsParser.ParseHints(req)
		var responseCode int
		if proteusHints != nil {
			// only status code is taken from hints, as the other parts of the response are stored in the DB
			responseCode = proteusHints.StatusCode
		} else {
			responseCode = endpoint.DefaultResponseStatusCode
		}

		resp, found := endpoint.Responses[strconv.Itoa(responseCode)]
		if !found {
			pr.sendNoContentResponse(w)
			return
		}

		respHeaders := resp.Headers
		for _, header := range respHeaders {
			for _, value := range header.Values {
				w.Header().Add(header.Name, value)
			}
		}

		respCookies := resp.Cookies
		for _, cookie := range respCookies {
			http.SetCookie(w, &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			})
		}

		respBodyAsString := ""
		if resp.Body != nil {
			if resp.Body.AsString != "" {
				respBodyAsString = resp.Body.AsString
			} else if resp.Body.AsBase64 != "" {
				decodedString, err := base64.StdEncoding.DecodeString(resp.Body.AsBase64)
				if err != nil {
					logger.Error("handleCustomRestEndpoint: failed to decode base64 string from the stored [asBase64] field value", err)
					pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
					return
				}
				respBodyAsString = string(decodedString)
			}
		}

		pr.sendResponseFromString(w, responseCode, respBodyAsString)
	}
}

func (pr *ProteusRouter) handleAnyReq(w http.ResponseWriter, req *http.Request) {
	proteusHints := pr.hintsParser.ParseHints(req)
	if proteusHints == nil {
		pr.sendJsonResponse(w, http.StatusOK, _200OkResponse)
	} else {
		pr.sendResponseFromHints(w, proteusHints)
	}
}

func (pr *ProteusRouter) handleSmartGetRequest(w http.ResponseWriter, domainPath string) {
	respBody, withId, err := pr.smartService.Get(domainPath)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
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

	id, err := pr.smartService.Create(domainPath, reqBodyAsMap)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	pr.sendJsonResponse(w, http.StatusCreated, models.SmartCreatedResponse{Id: string(id)})
}

func (pr *ProteusRouter) handleSmartUpdateRequest(w http.ResponseWriter, domainPath string, reqBodyAsMap map[string]interface{}) {
	if reqBodyAsMap == nil || len(reqBodyAsMap) == 0 {
		pr.sendJsonErrorResponse(w, http.StatusBadRequest, common.ErrorInvalidRequestBody, common.ErrorCodeInvalidRequestBody)
		return
	}

	found, err := pr.smartService.Update(domainPath, reqBodyAsMap)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
	if !found {
		pr.sendJsonErrorResponse(w, http.StatusNotFound, fmt.Sprintf(common.ErrorNotFoundSmartPath, domainPath), common.ErrorCodeNotFoundSmartPath)
		return
	}
	pr.sendNoContentResponse(w)
}

func (pr *ProteusRouter) handleSmartDeleteRequest(w http.ResponseWriter, domainPath string) {
	found, err := pr.smartService.Delete(domainPath)
	if err != nil {
		pr.sendJsonErrorResponse(w, http.StatusInternalServerError, common.ErrorInternalServerError, common.ErrorCodeInternalInvalidRequestPath)
		return
	}
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

func (pr *ProteusRouter) parseApiKeyCreds(req *http.Request, proteusHints models.ProteusHints) *models.ApiKeyAuthCredentialsInstance {
	apiKeyName := proteusHints.ApiKey.KeyName
	apiKeyLocation := proteusHints.ApiKey.Location
	if apiKeyLocation == "" {
		apiKeyLocation = "header"
	}

	apiKey := ""
	switch apiKeyLocation {
	case "header":
		apiKey = req.Header.Get(apiKeyName)
	case "query":
		apiKey = req.URL.Query().Get(apiKeyName)
	}

	if apiKey == "" {
		logger.Error("parseApiKeyCreds: no API key provided")
		return nil
	}

	if proteusHints.ApiKey.ValueFormat == "base64" {
		decodedString, err := base64.StdEncoding.DecodeString(apiKey)
		if err != nil {
			logger.Error("parseApiKeyCreds: failed to decode base64 string from the provided API key", err)
			return nil
		}
		apiKey = string(decodedString)
	}

	if proteusHints.ApiKey.ValueParserRegexp != nil {
		match := proteusHints.ApiKey.ValueParserRegexp.FindStringSubmatch(apiKey)
		if len(match) == 0 {
			logger.Error("parseApiKeyCreds: failed to parse API key with the provided regexp")
			return nil
		}
		apiKey = match[1]
	}
	return &models.ApiKeyAuthCredentialsInstance{
		KeyName:  apiKeyName,
		KeyValue: apiKey,
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

func (pr *ProteusRouter) sendResponseFromHints(w http.ResponseWriter, hints *models.ProteusHints) {
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

func (pr *ProteusRouter) sendResponseFromString(w http.ResponseWriter, httpCode int, respBody string) {
	w.WriteHeader(httpCode)

	if respBody != "" {
		w.Write([]byte(respBody))
	}
}

func (pr *ProteusRouter) sendUnauthorizedResponse(w http.ResponseWriter) {
	pr.sendJsonResponse(w, http.StatusUnauthorized, forStatusCode(http.StatusUnauthorized))
}

func (pr *ProteusRouter) sendJsonErrorResponse(w http.ResponseWriter, httpCode int, message string, errorCode string) {
	pr.sendJsonResponse(w, httpCode, models.ErrorResponse{Message: message, Code: errorCode})
}
