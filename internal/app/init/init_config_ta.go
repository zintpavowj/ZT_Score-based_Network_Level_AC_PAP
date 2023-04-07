// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_config.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PAP/internal/app/config"
)

// The function initializes the 'pe' section of the config file and
// loads the Policy Engine certificate(s).
func initPe(sysLogger *logrus.Logger) error {
	var err error
	var fields string = ""

	if config.Config.Pap.ListenAddr == "" {
		fields += "listen_addr,"
	}

	if config.Config.Pap.SSLCert == "" {
		fields += "ssl_cert,"
	}

	if config.Config.Pap.SSLCertKey == "" {
		fields += "ssl_cert_key,"
	}

	if config.Config.Pap.CACertsToVerifyClientRequests == nil {
		fields += "ca_certs_to_verify_client_certs,"
	}

	if fields != "" {
		return fmt.Errorf("initPe(): in the section 'pe' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used to verify certs to be accepted
	for _, acceptedClientCert := range config.Config.Pap.CACertsToVerifyClientRequests {
		err = loadCACertificate(sysLogger, acceptedClientCert, "client", config.Config.CACertPoolToVerifyClientRequests)
		if err != nil {
			return err
		}
	}

	// Load Policy Engine certificate
	config.Config.PeCert, err = loadX509KeyPair(sysLogger, config.Config.Pap.SSLCert, config.Config.Pap.SSLCertKey, "Policy Engine", "")
	if err != nil {
		return err
	}

	return nil
}
