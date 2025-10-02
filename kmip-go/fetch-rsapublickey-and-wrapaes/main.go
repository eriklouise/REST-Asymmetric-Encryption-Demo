package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ovh/kmip-go/kmipclient"
)

// Config represents the structure of the config.json file.
type Config struct {
	KMIPHost         string `json:"kmip_host"`
	ClientCert       string `json:"client_cert"`
	ClientKey        string `json:"client_key"`
	CACert           string `json:"ca_cert"`
	KeyName          string `json:"key_name"`
	KeyLength        int    `json:"key_length"`
	PublicKeyIDFile  string `json:"public_keyid_file"`
	PrivateKeyIDFile string `json:"private_keyid_file"`
	AESKeyFile       string `json:"aes_key_file"`
	AESIVFile        string `json:"aes_iv_file"`
	AESWrappedFile   string `json:"aes_wrapped_file"`
}

// loadConfig reads the configuration from the specified JSON file.
func loadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}
	return &cfg, nil
}

func main() {
	// 1. LOAD CONFIGURATION
	cfg, err := loadConfig("../config.json")
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	fmt.Printf("Loaded configuration: %+v\n", cfg)

	// Connect with comprehensive options
	client, err := kmipclient.Dial(
		cfg.KMIPHost,

		// TLS Configuration
		kmipclient.WithRootCAFile(cfg.CACert), // Custom CA certificate
		kmipclient.WithClientCertFiles(cfg.ClientCert, cfg.ClientKey),
	)

	if err != nil {
		log.Fatalf("Failed to connect to KMIP server: %v", err)
	}

	// Find keys by id
	keys := client.Locate().
		WithName(fmt.Sprintf("%s_Public", cfg.KeyName)).
		MustExec()

	for _, keyID := range keys.UniqueIdentifier {
		fmt.Printf("Found key: %s\n", keyID)

		// Get all attributes
		allAttrs := client.GetAttributes(keyID).MustExec()

		for _, attr := range allAttrs.Attribute {
			fmt.Printf("Attribute: %s = %v\n", attr.AttributeName, attr.AttributeValue)
		}
	}

	if err != nil {
		log.Fatalf("Failed to connect to KMIP server: %v", err)
	}
}
