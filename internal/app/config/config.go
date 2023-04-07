package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config contains all input from the config file and is is globally accessible
var (
	Config ConfigT
)

// The struct PeT is for parsing the section 'pe' of the config file.
type PapT struct {
	ListenAddr                    string   `yaml:"listen_addr"`
	SSLCert                       string   `yaml:"ssl_cert"`
	SSLCertKey                    string   `yaml:"ssl_cert_key"`
	CACertsToVerifyClientRequests []string `yaml:"ca_certs_to_verify_client_certs"`
}

// ConfigT struct is for parsing the basic structure of the config file
type ConfigT struct {
	SysLogger                        sysLoggerT `yaml:"system_logger"`
	Pap                              PapT       `yaml:"pap"`
	CACertPoolToVerifyClientRequests *x509.CertPool
	PeCert                           tls.Certificate
}

type sysLoggerT struct {
	LogLevel       string `yaml:"level"`
	LogDestination string `yaml:"destination"`
	LogFormatter   string `yaml:"formatter"`
}

// LoadConfig() parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string) error {
	// If the config file path was not provided
	if configPath == "" {
		return errors.New("no configuration file is provided")
	}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to open the YAML configuration file '%s': %w", configPath, err)
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Decode configuration from the YAML config file
	err = d.Decode(&Config)
	if err != nil {
		return fmt.Errorf("unable to decode the YAML configuration file '%s': %w", configPath, err)
	}
	return nil
}
