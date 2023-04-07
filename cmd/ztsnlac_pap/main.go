package main

import (
	"crypto/x509"
	"flag"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PAP/internal/app/config"
	confInit "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PAP/internal/app/init"
	logger "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PAP/internal/app/logger"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PAP/internal/app/router"
)

var (
	confFilePath string
	sysLogger    *logrus.Logger
)

func init() {
	var err error

	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "./config/config.yml", "Path to user defined YML config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = config.LoadConfig(confFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// init system logger
	confInit.InitSysLoggerParams()

	// Create an instance of the system logger
	sysLogger = logrus.New()

	logger.SetLoggerDestination(sysLogger)
	logger.SetLoggerLevel(sysLogger)
	logger.SetLoggerFormatter(sysLogger)
	logger.SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading logger configuration from '%s' - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the Policy Engine
	config.Config.CACertPoolToVerifyClientRequests = x509.NewCertPool()

	if err = confInit.InitConfig(sysLogger); err != nil {
		sysLogger.Fatalf("main: init(): %s", err.Error())
	}
}

func main() {
	// Create new PAP router
	papRouter, err := router.New(sysLogger)
	if err != nil {
		sysLogger.Fatalf("main: unable to create a new router: %s", err.Error())
	}
	sysLogger.Debug("main: new router was successfully created")

	err = papRouter.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: ListenAndServeTLS() fatal error: %s", err.Error())
	}
}
