package httpserver

import (
	"context"
	"errors"
	"github.com/n0rdy/proteus/httpserver/api"
	"github.com/n0rdy/proteus/httpserver/service/logger"
	"net/http"
	"strconv"
)

func Start(port int) {
	portAsString := strconv.Itoa(port)
	log := logger.NewConsoleLogger()
	shutdownCh := make(chan struct{})
	restartCh := make(chan struct{})

	proteusRouter := api.NewProteusRouter(log, shutdownCh, restartCh)
	httpRouter := proteusRouter.NewRouter()

	log.Info("http: starting server at port " + portAsString)

	server := &http.Server{Addr: "localhost:" + portAsString, Handler: httpRouter}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			close(shutdownCh)
			close(restartCh)
			if errors.Is(err, http.ErrServerClosed) {
				log.Info("server shutdown")
			} else {
				log.Error("server failed", err)
			}
		}
	}()

	select {
	case <-shutdownCh:
		log.Info("server shutdown requested")
		shutdownServer(server)
	case <-restartCh:
		log.Info("server restart requested")
		shutdownServer(server)
		Start(port)
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
