package httpserver

import (
	"context"
	"errors"
	"github.com/n0rdy/proteus/common"
	"github.com/n0rdy/proteus/httpserver/api"
	"github.com/n0rdy/proteus/httpserver/service/auth/apikey"
	"github.com/n0rdy/proteus/httpserver/service/auth/basic"
	"github.com/n0rdy/proteus/httpserver/service/auth/db"
	"github.com/n0rdy/proteus/httpserver/service/endpoints"
	"github.com/n0rdy/proteus/httpserver/service/generator"
	"github.com/n0rdy/proteus/httpserver/service/hints"
	"github.com/n0rdy/proteus/httpserver/service/smart"
	"github.com/n0rdy/proteus/logger"
	"net/http"
	"strconv"
)

func Start(port int, conf *common.Conf) {
	authDb, err := db.NewAuthDb()
	if err != nil {
		logger.Error("failed to create auth db", err)
		return
	}
	defer authDb.Close()

	basicAuthService := basic.NewService(authDb)
	apiKeyAuthService := apikey.NewService(authDb)

	endpointService, err := endpoints.NewService()
	if err != nil {
		logger.Error("failed to create endpoints service", err)
		return
	}
	defer endpointService.Close()

	smartService, err := smart.NewService()
	if err != nil {
		logger.Error("failed to create smart service", err)
		return
	}
	defer smartService.Close()

	hintsParser := &hints.ProteusHintsParser{}
	hintsParser.Init(conf)

	randomDataGenerator := &generator.RandomDataGenerator{}
	restEndpointsGenerator := generator.NewRestEndpointsGenerator(randomDataGenerator)

	portAsString := strconv.Itoa(port)
	shutdownCh := make(chan struct{})
	restartCh := make(chan struct{})

	proteusRouter := api.NewProteusRouter(basicAuthService, apiKeyAuthService, smartService, endpointService, hintsParser, restEndpointsGenerator, shutdownCh, restartCh)
	httpRouter := proteusRouter.NewRouter()

	logger.Info("http: starting server at port " + portAsString)

	server := &http.Server{Addr: "localhost:" + portAsString, Handler: httpRouter}
	go func() {
		err = server.ListenAndServe()
		if err != nil {
			close(shutdownCh)
			close(restartCh)
			if errors.Is(err, http.ErrServerClosed) {
				logger.Info("server shutdown")
			} else {
				logger.Error("server failed", err)
			}
		}
	}()

	select {
	case <-shutdownCh:
		logger.Info("server shutdown requested")
		shutdownServer(server)
	case <-restartCh:
		logger.Info("server restart requested")
		shutdownServer(server)
		endpointService.Close()
		smartService.Close()
		authDb.Close()
		Start(port, conf)
	}
}

func shutdownServer(server *http.Server) {
	err := server.Shutdown(context.Background())
	if err != nil {
		err := server.Close()
		if err != nil {
			return
		}
	}
}
