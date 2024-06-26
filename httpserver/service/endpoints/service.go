package endpoints

import (
	"github.com/n0rdy/proteus/httpserver/models"
	"github.com/n0rdy/proteus/httpserver/service/endpoints/db"
	"github.com/n0rdy/proteus/httpserver/utils"
	"github.com/n0rdy/proteus/logger"
	"strings"
)

type Service struct {
	edb *db.EndpointsDb
}

func NewService() (*Service, error) {
	boltDb, err := db.NewEndpointsDb()
	if err != nil {
		return nil, err
	}
	return &Service{edb: boltDb}, nil
}

func (s *Service) Close() error {
	return s.edb.Close()
}

func (s *Service) GetAllRestEndpoints() ([]models.RestEndpoint, error) {
	return s.edb.GetAllRest()
}

func (s *Service) GetRestEndpoint(method string, path string) (*models.RestEndpoint, error) {
	return s.edb.GetOneRest(method, path)
}

func (s *Service) AddRestEndpoint(endpoint models.RestEndpoint) error {
	if s.isReservedPath(endpoint.Path) {
		return utils.ErrReservedPath
	}
	if s.isContentTypeDuplicated(endpoint) {
		return utils.ErrDuplicatedContentType
	}
	return s.edb.InsertOneRest(endpoint)
}

func (s *Service) DeleteAllRestEndpoints() error {
	return s.edb.DeleteAllRest()
}

func (s *Service) DeleteRestEndpoint(method string, path string) (found bool, err error) {
	restEndpoint, err := s.edb.GetOneRest(method, path)
	if err != nil {
		return false, err
	}
	if restEndpoint == nil {
		return false, nil
	}
	return true, s.edb.DeleteOneRest(method, path)
}

func (s *Service) UpdateRestEndpoint(method string, path string, endpoint models.RestEndpoint) (found bool, err error) {
	restEndpoint, err := s.edb.GetOneRest(method, path)
	if err != nil {
		return false, err
	}
	if restEndpoint == nil {
		return false, nil
	}
	return true, s.edb.InsertOneRest(endpoint)
}

func (s *Service) isReservedPath(path string) bool {
	return strings.HasPrefix(path, utils.ProteusReservedApiPath)
}

func (s *Service) isContentTypeDuplicated(endpoint models.RestEndpoint) bool {
	for code, response := range endpoint.Responses {
		seenMediaTypesForCode := make(map[string]bool)
		for _, body := range response.Body {
			if _, exists := seenMediaTypesForCode[body.ContentType]; exists {
				logger.Error("service: duplicated content type [" + body.ContentType + "] for HTTP status code: [" + code + "]")
				return true
			}
			seenMediaTypesForCode[body.ContentType] = true
		}
	}
	return false
}
