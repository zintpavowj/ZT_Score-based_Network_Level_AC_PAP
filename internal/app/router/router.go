// Package router contains the main routine of the PIP service.
package router

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PAP/internal/app/config"
)

type PapPolicy struct {
	Algorithm string `json:"algorithm"`
	Threshold string `json:"threshold"`
}

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logrus.Logger
	papPolicy PapPolicy
}

func New(logger *logrus.Logger) (*Router, error) {
	router := new(Router)
	router.papPolicy = PapPolicy{
		Algorithm: "additive",
		Threshold: "static",
	}

	// Set sysLogger to the one created in the init function
	router.sysLogger = logger

	// Configure the TLS configuration of the router
	router.tlsConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    config.Config.CACertPoolToVerifyClientRequests,
		Certificates: []tls.Certificate{config.Config.PeCert},
	}

	// Frontend Handlers
	mux := mux.NewRouter()
	mux.HandleFunc("/", router.handleGetPolicies()).Methods("GET")
	mux.HandleFunc("/", router.handleSetPolicies()).Methods("POST")

	mux.HandleFunc("/algorithm", router.handleGetAlgorithm()).Methods("GET")
	mux.HandleFunc("/algorithm", router.handleSetAlgorithm()).Methods("POST")

	mux.HandleFunc("/threshold", router.handleGetThreshold()).Methods("GET")
	mux.HandleFunc("/threshold", router.handleSetThreshold()).Methods("POST")

	w := logger.Writer()

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         config.Config.Pap.ListenAddr,
		TLSConfig:    router.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(w, "", 0),
	}

	return router, nil
}

// ServeHTTP() handles all incoming requests
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
}

// ListenAndServeTLS() is a wraper to the original http.ListenAndServeTLS
func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}

func (router *Router) handleGetPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := json.NewEncoder(w).Encode(router.papPolicy)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			router.sysLogger.WithFields(logrus.Fields{
				"package":    "router",
				"function":   "handleGetPolicies",
				"httpStatus": http.StatusInternalServerError,
			}).Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
	}
}

func (router *Router) handleSetPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var data PapPolicy
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			router.sysLogger.WithFields(logrus.Fields{
				"package":    "router",
				"function":   "handleGetPolicies",
				"httpStatus": http.StatusBadRequest,
			}).Error(err)
		}
		router.papPolicy = data
	}
}

func (router *Router) handleGetAlgorithm() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := json.NewEncoder(w).Encode(router.papPolicy.Algorithm)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			router.sysLogger.WithFields(logrus.Fields{
				"package":    "router",
				"function":   "handleGetAlgorithm",
				"httpStatus": http.StatusInternalServerError,
			}).Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
	}
}

func (router *Router) handleSetAlgorithm() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var data string
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			router.sysLogger.WithFields(logrus.Fields{
				"package":    "router",
				"function":   "handleGetPolicies",
				"httpStatus": http.StatusBadRequest,
			}).Error(err)
		}
		router.papPolicy.Algorithm = data
	}
}

func (router *Router) handleGetThreshold() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := json.NewEncoder(w).Encode(router.papPolicy.Threshold)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			router.sysLogger.WithFields(logrus.Fields{
				"package":    "router",
				"function":   "handleGetThreshold",
				"httpStatus": http.StatusInternalServerError,
			}).Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
	}
}

func (router *Router) handleSetThreshold() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var data string
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			router.sysLogger.WithFields(logrus.Fields{
				"package":    "router",
				"function":   "handleGetPolicies",
				"httpStatus": http.StatusBadRequest,
			}).Error(err)
		}
		router.papPolicy.Threshold = data
	}
}
