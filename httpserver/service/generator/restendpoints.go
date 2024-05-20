package generator

import (
	"encoding/json"
	"errors"
	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/utils"
	"github.com/n0rdy/proteus/httpserver/utils/xmlp"
	"github.com/n0rdy/proteus/logger"
	commonUtils "github.com/n0rdy/proteus/utils"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

var (
	supportedMediaTypes = map[string]bool{
		"application/json": true,
		"application/xml":  true,
	}
)

type RestEndpointsGenerator struct {
	randomDataGenerator *RandomDataGenerator
}

func NewRestEndpointsGenerator(randomDataGenerator *RandomDataGenerator) *RestEndpointsGenerator {
	return &RestEndpointsGenerator{
		randomDataGenerator: randomDataGenerator,
	}
}

func (reg *RestEndpointsGenerator) FromOpenApiV3File(pathToOpenApi string) ([]models.RestEndpoint, error) {
	loader := openapi3.NewLoader()
	// allows visiting other files referenced in the OpenAPI document
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromFile(pathToOpenApi)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to load OpenAPI document: ["+pathToOpenApi+"]", err)
		return nil, err
	}

	if err = doc.Validate(loader.Context); err != nil {
		logger.Error("RestEndpointsGenerator: OpenAPI document is not valid: ["+pathToOpenApi+"]", err)
		return nil, err
	}
	return reg.fromOpenApiV3(doc)
}

func (reg *RestEndpointsGenerator) FromOpenApiV3Url(urlOpenApi string) ([]models.RestEndpoint, error) {
	loader := openapi3.NewLoader()
	// allows visiting other files referenced in the OpenAPI document
	loader.IsExternalRefsAllowed = true

	parsedUrl, err := url.Parse(urlOpenApi)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to parse OpenAPI URL: ["+urlOpenApi+"]", err)
		return nil, err
	}

	doc, err := loader.LoadFromURI(parsedUrl)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to load OpenAPI document: ["+urlOpenApi+"]", err)
		return nil, err
	}

	if err = doc.Validate(loader.Context); err != nil {
		logger.Error("RestEndpointsGenerator: OpenAPI document is not valid: ["+urlOpenApi+"]", err)
		return nil, err
	}
	return reg.fromOpenApiV3(doc)
}

func (reg *RestEndpointsGenerator) FromOpenApiV3Content(openApi []byte) ([]models.RestEndpoint, error) {
	loader := openapi3.NewLoader()
	// allows visiting other files referenced in the OpenAPI document
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromData(openApi)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to load OpenAPI document", err)
		return nil, err
	}

	if err = doc.Validate(loader.Context); err != nil {
		logger.Error("RestEndpointsGenerator: OpenAPI document is not valid", err)
		return nil, err
	}
	return reg.fromOpenApiV3(doc)
}

func (reg *RestEndpointsGenerator) FromSwaggerV2File(pathToSwagger string) ([]models.RestEndpoint, error) {
	input, err := os.ReadFile(pathToSwagger)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to read Swagger file: ["+pathToSwagger+"]", err)
		return nil, err
	}

	var doc openapi2.T
	if err = json.Unmarshal(input, &doc); err != nil {
		logger.Error("RestEndpointsGenerator: failed to unmarshal Swagger file: ["+pathToSwagger+"]", err)
		return nil, err
	}

	openApiDoc, err := openapi2conv.ToV3(&doc)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to convert Swagger to OpenAPI v3", err)
		return nil, err
	}
	return reg.fromOpenApiV3(openApiDoc)
}

func (reg *RestEndpointsGenerator) FromSwaggerV2Url(urlSwagger string) ([]models.RestEndpoint, error) {
	parsedUrl, err := url.Parse(urlSwagger)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to parse Swagger URL: ["+urlSwagger+"]", err)
		return nil, err
	}

	resp, err := http.Get(parsedUrl.String())
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to fetch Swagger content from URL: ["+urlSwagger+"]", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("RestEndpointsGenerator: failed to fetch Swagger content from URL: [" + urlSwagger + "] - status code: [" + strconv.Itoa(resp.StatusCode) + "]")
		return nil, errors.New("failed to fetch Swagger content from URL: [" + urlSwagger + "] - status code: [" + strconv.Itoa(resp.StatusCode) + "]")
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to read Swagger content from URL: ["+urlSwagger+"]", err)
		return nil, err
	}

	return reg.FromSwaggerV2Content(content)
}

func (reg *RestEndpointsGenerator) FromSwaggerV2Content(swagger []byte) ([]models.RestEndpoint, error) {
	var doc openapi2.T
	if err := json.Unmarshal(swagger, &doc); err != nil {
		logger.Error("RestEndpointsGenerator: failed to unmarshal Swagger content", err)
		return nil, err
	}

	openApiDoc, err := openapi2conv.ToV3(&doc)
	if err != nil {
		logger.Error("RestEndpointsGenerator: failed to convert Swagger to OpenAPI v3", err)
		return nil, err
	}
	return reg.fromOpenApiV3(openApiDoc)
}

func (reg *RestEndpointsGenerator) fromOpenApiV3(openApiDoc *openapi3.T) ([]models.RestEndpoint, error) {
	result := make([]models.RestEndpoint, 0)
	paths := openApiDoc.Paths.Map()
	orderedPathUris := openApiDoc.Paths.InMatchingOrder()
	for _, uri := range orderedPathUris {
		pathItem := paths[uri]
		logger.Debug("RestEndpointsGenerator: processing path: [" + uri + "]")

		endpoints, err := reg.toRestEndpoints(pathItem, uri)
		if err != nil {
			return nil, err
		}
		result = append(result, endpoints...)
	}
	return result, nil
}

func (reg *RestEndpointsGenerator) toRestEndpoints(pathItem *openapi3.PathItem, pathUri string) ([]models.RestEndpoint, error) {
	result := make([]models.RestEndpoint, 0)
	if pathItem == nil {
		return result, nil
	}

	if pathItem.Get != nil {
		re, err := reg.toRestEndpoint(*pathItem.Get, pathUri, http.MethodGet)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Post != nil {
		re, err := reg.toRestEndpoint(*pathItem.Post, pathUri, http.MethodPost)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Put != nil {
		re, err := reg.toRestEndpoint(*pathItem.Put, pathUri, http.MethodPut)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Delete != nil {
		re, err := reg.toRestEndpoint(*pathItem.Delete, pathUri, http.MethodDelete)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Patch != nil {
		re, err := reg.toRestEndpoint(*pathItem.Patch, pathUri, http.MethodPatch)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Head != nil {
		re, err := reg.toRestEndpoint(*pathItem.Head, pathUri, http.MethodHead)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Options != nil {
		re, err := reg.toRestEndpoint(*pathItem.Options, pathUri, http.MethodOptions)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Connect != nil {
		re, err := reg.toRestEndpoint(*pathItem.Connect, pathUri, http.MethodConnect)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	if pathItem.Trace != nil {
		re, err := reg.toRestEndpoint(*pathItem.Trace, pathUri, http.MethodTrace)
		if err != nil {
			return nil, err
		}
		result = append(result, *re)
	}
	return result, nil
}

func (reg *RestEndpointsGenerator) toRestEndpoint(operation openapi3.Operation, pathUri string, httpMethod string) (*models.RestEndpoint, error) {
	logger.Debug("RestEndpointsGenerator: processing endpoint: [" + httpMethod + "] " + pathUri)

	var defaultResponseStatusCode int
	responses := make(map[string]models.RestEndpointResponseStructure)
	if operation.Responses != nil {
		for code, resp := range operation.Responses.Map() {
			if !commonUtils.IsHttpCodeValid(code) {
				logger.Error("RestEndpointsGenerator: response code is not valid: [" + code + "] - skipping it")
				return nil, errors.New("response code is not valid: [" + code + "]")
			}
			if resp.Value == nil {
				logger.Warn("RestEndpointsGenerator: response value is nil for code: [" + code + "] - skipping it")
				continue
			}
			httpCode, _ := strconv.Atoi(code)
			headers := reg.toHeaders(resp.Value.Headers)

			var respBody []models.RestEndpointResponseBody
			if !commonUtils.IsNoResponseBodyHttpCode(httpCode) {
				var err error
				respBody, err = reg.toResponseBody(resp.Value.Content)
				if err != nil {
					return nil, err
				}
			}

			responses[code] = models.RestEndpointResponseStructure{
				Body:    respBody,
				Headers: headers,
			}
			defaultResponseStatusCode = reg.toDefaultHttpStatusCode(defaultResponseStatusCode, httpCode)
		}
	}

	if defaultResponseStatusCode == 0 {
		logger.Warn("RestEndpointsGenerator: default response status code is not set - no valid responses found for the operation")
		return nil, errors.New("default response status code is not set")
	}

	return &models.RestEndpoint{
		Path:                      pathUri,
		Method:                    httpMethod,
		Description:               reg.toDescription(operation.Summary, operation.Description),
		DefaultResponseStatusCode: defaultResponseStatusCode,
		Responses:                 responses,
	}, nil
}

func (reg *RestEndpointsGenerator) toHeaders(headers openapi3.Headers) []models.RestEndpointHeader {
	result := make([]models.RestEndpointHeader, 0)
	if headers == nil {
		return result
	}
	for name, header := range headers {
		restHeader := reg.toHeader(name, header.Value)
		if restHeader == nil {
			continue
		}
		result = append(result, *restHeader)
	}
	return result
}

func (reg *RestEndpointsGenerator) toHeader(name string, openApiHeader *openapi3.Header) *models.RestEndpointHeader {
	if openApiHeader == nil || openApiHeader.Schema == nil || openApiHeader.Schema.Value == nil || openApiHeader.Schema.Value.Type == nil {
		logger.Warn("RestEndpointsGenerator: OpenAPI header value is nil for name: [" + name + "] - skipping it")
		return nil
	}

	headerTypes := openApiHeader.Schema.Value.Type
	if !headerTypes.Includes(openapi3.TypeString) {
		// based on the specs, HTTP header must always be a string: https://stackoverflow.com/a/50676124
		logger.Warn("RestEndpointsGenerator: OpenAPI header type is not string for name: [" + name + "] - skipping it")
		return nil
	}

	var headerValue string
	headerExample := openApiHeader.Schema.Value.Example
	if headerExample != nil {
		if str, ok := headerExample.(string); ok {
			headerValue = str
		}
	}

	// TODO: consider generating data based on the header name: define default values for common headers
	if headerValue == "" {
		headerValue = reg.randomDataGenerator.RandomString()
	}
	return &models.RestEndpointHeader{
		Name:   name,
		Values: []string{headerValue},
	}
}

func (reg *RestEndpointsGenerator) toResponseBody(content openapi3.Content) ([]models.RestEndpointResponseBody, error) {
	result := make([]models.RestEndpointResponseBody, 0)

	// can be the case for 204 No Content and similar responses
	if content == nil || len(content) == 0 {
		return nil, nil
	}

	for ct, mt := range content {
		if !supportedMediaTypes[ct] {
			logger.Warn("RestEndpointsGenerator: unsupported media type: [" + ct + "] - skipping the content type entirely")
			continue
		}
		if mt == nil {
			logger.Warn("RestEndpointsGenerator: media type is nil for content type: [" + ct + "] - skipping the content type entirely")
			continue
		}

		if mt.Example != nil {
			respBody, err := reg.responseBodyFromExample(mt.Example, ct)
			if err != nil || respBody == nil {
				logger.Warn("RestEndpointsGenerator: failed to generate response body from example for content type: [" + ct + "] from the `example` property - skipping the example and trying other options")
			} else {
				result = append(result, *respBody)
				continue
			}
		}

		if mt.Examples != nil {
			respBody, err := reg.responseBodyFromExample(mt.Examples[ct], ct)
			if err != nil || respBody == nil {
				logger.Warn("RestEndpointsGenerator: failed to generate response body from example for content type: [" + ct + "] from the `examples` property - skipping the example and trying other options")
			} else {
				result = append(result, *respBody)
				continue
			}
		}

		if mt.Schema != nil && mt.Schema.Value != nil {
			if mt.Schema.Value.Example != nil {
				respBody, err := reg.responseBodyFromExample(mt.Schema.Value.Example, ct)
				if err != nil || respBody == nil {
					logger.Warn("RestEndpointsGenerator: failed to generate response body from schema example for content type: [" + ct + "] - skipping it")
					continue
				}
				result = append(result, *respBody)
				continue
			}

			respBody, err := reg.responseBodyFromSchema(mt.Schema.Value, ct)
			if err != nil || respBody == nil {
				logger.Warn("RestEndpointsGenerator: failed to generate response body from schema for content type: [" + ct + "] - skipping it")
				continue
			}
			result = append(result, *respBody)
			continue
		}
		logger.Warn("RestEndpointsGenerator: no valid response body found for content type: [" + ct + "] - skipping the content type entirely")
	}
	return result, nil
}

func (reg *RestEndpointsGenerator) responseBodyFromExample(example interface{}, contentType string) (*models.RestEndpointResponseBody, error) {
	if example == nil {
		return nil, nil
	}

	var respBodyAsBytes []byte
	var err error
	switch utils.SanitizeContentType(contentType) {
	case "application/json":
		respBodyAsBytes, err = json.Marshal(example)
	case "application/xml":
		respBodyAsBytes, err = xmlp.Marshal(example)
	}

	if err != nil {
		return nil, err
	}
	if respBodyAsBytes == nil {
		return nil, nil
	}

	return &models.RestEndpointResponseBody{
		ContentType: contentType,
		AsString:    string(respBodyAsBytes),
	}, nil
}

func (reg *RestEndpointsGenerator) responseBodyFromSchema(respBodySchema *openapi3.Schema, contentType string) (*models.RestEndpointResponseBody, error) {
	parsedSchema, err := reg.traverseSchema(respBodySchema)
	if err != nil {
		return nil, err
	}

	var respBodyAsBytes []byte
	switch utils.SanitizeContentType(contentType) {
	case "application/json":
		respBodyAsBytes, err = json.Marshal(parsedSchema)
	case "application/xml":
		respBodyAsBytes, err = xmlp.Marshal(parsedSchema)
	}

	if err != nil {
		return nil, err
	}
	if respBodyAsBytes == nil {
		return nil, nil
	}
	return &models.RestEndpointResponseBody{
		ContentType: contentType,
		AsString:    string(respBodyAsBytes),
	}, nil
}

func (reg *RestEndpointsGenerator) traverseSchema(schema *openapi3.Schema) (interface{}, error) {
	if schema == nil || schema.Type == nil || len(schema.Type.Slice()) == 0 {
		logger.Warn("RestEndpointsGenerator: schema is nil or has no type - skipping it")
		return nil, utils.ErrNoTypeSpecifiedOpenApi
	}

	if len(schema.Type.Slice()) > 1 {
		logger.Warn("RestEndpointsGenerator: schema has multiple types, it's not supported by Proteus - skipping it")
		return nil, utils.ErrNoTypeSpecifiedOpenApi
	}

	schemaType := schema.Type.Slice()[0]
	switch schemaType {
	case openapi3.TypeObject:
		var result map[string]interface{}
		if schema.Properties != nil {
			result = make(map[string]interface{})
			for name, prop := range schema.Properties {
				if prop == nil {
					logger.Warn("RestEndpointsGenerator: property is nil for name: [" + name + "] - skipping it")
					continue
				}
				propValue, err := reg.traverseSchema(prop.Value)
				if err != nil {
					return nil, err
				}
				result[name] = propValue
			}
			return result, nil
		}
	case openapi3.TypeArray:
		if schema.Items == nil || schema.Items.Value == nil {
			logger.Warn("RestEndpointsGenerator: items are nil for array schema - skipping it")
			return nil, utils.ErrNoItemsSpecifiedOpenApi
		}
		itemsValue, err := reg.traverseSchema(schema.Items.Value)
		if err != nil {
			return nil, err
		}
		return []interface{}{itemsValue}, nil
	case openapi3.TypeString:
		if schema.Example != nil {
			if str, ok := schema.Example.(string); ok {
				return str, nil
			}
		}
		if schema.Enum != nil && len(schema.Enum) > 0 {
			if str, ok := schema.Enum[0].(string); ok {
				return str, nil
			}
		}
		return reg.randomDataGenerator.RandomString(), nil
	case openapi3.TypeInteger:
		if schema.Example != nil {
			if num, ok := schema.Example.(int); ok {
				return num, nil
			}
		}
		return reg.randomDataGenerator.RandomInt(), nil
	case openapi3.TypeNumber:
		if schema.Example != nil {
			if num, ok := schema.Example.(float64); ok {
				return num, nil
			}
		}
		return reg.randomDataGenerator.RandomFloat(), nil
	case openapi3.TypeBoolean:
		return reg.randomDataGenerator.RandomBool(), nil
	case openapi3.TypeNull:
		return nil, nil
	default:
		logger.Warn("RestEndpointsGenerator: unsupported schema type: [" + schemaType + "] - skipping it")
		return nil, utils.ErrUnsupportedSchemaTypeOpenApi
	}
	return nil, nil
}

// toDefaultHttpStatusCode returns the default HTTP status code based on the current default and processed status codes
// The idea is to go with:
// - 2xx as a top priority: the lower, the better
// - 1xx as a second priority: the lower, the better
// - 3xx as a third priority: the lower, the better
// - 4xx as a fourth priority: no matter what, it's better than 5xx
// - 5xx as a fifth priority: no matter what, it's the worst
func (reg *RestEndpointsGenerator) toDefaultHttpStatusCode(currentDefault int, currentProcessed int) int {
	if currentDefault == 0 {
		return currentProcessed
	}

	if commonUtils.Is2xxHttpCode(currentDefault) {
		if commonUtils.Is2xxHttpCode(currentProcessed) {
			return commonUtils.MinInt(currentDefault, currentProcessed)
		}
		return currentDefault
	}
	if commonUtils.Is2xxHttpCode(currentProcessed) {
		return currentProcessed
	}
	return commonUtils.MinInt(currentDefault, currentProcessed)
}

func (reg *RestEndpointsGenerator) toDescription(summary string, description string) string {
	if summary != "" && description != "" {
		return summary + ". " + description
	}
	if summary != "" {
		return summary
	}
	return description
}
