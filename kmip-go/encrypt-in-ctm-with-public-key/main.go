package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/ttlv"
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

func encryptAesKeyWithRsaKey() {
	// 1.LOAD CONFIGURATION
	cfg, err := loadConfig("../config.json")
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	fmt.Printf("Loaded configuration: %+v\n", cfg)

	// 2. CONNECT TO THE KMIP SERVER
	c, err := kmipclient.Dial(
		cfg.KMIPHost,

		// TLS Configuration
		kmipclient.WithRootCAFile(cfg.CACert), // Custom CA certificate
		kmipclient.WithClientCertFiles(cfg.ClientCert, cfg.ClientKey),
	)

	log.Printf("Successfully connected to KMIP server at %s", cfg.KMIPHost)

	// 3. READ THE AES KEY MATERIAL FROM FILE
	aesKeyMaterial, err := os.ReadFile(cfg.AESKeyFile)
	if err != nil {
		log.Fatalf("Failed to read AES key file %s: %v", cfg.AESKeyFile, err)
	}
	log.Printf("Read %d bytes of AES key material from %s.", len(aesKeyMaterial), cfg.AESKeyFile)

	// 4. READ THE RSA KEY UNIQUE ID
	rsaPubKeyId, err := os.ReadFile(cfg.PublicKeyIDFile) // returns []byte
	if err != nil {
		panic(err)
	}
	fmt.Printf("File has %d bytes\n", len(rsaPubKeyId))
	fmt.Println(rsaPubKeyId) // raw bytes

	// 5. CONSTRUCT THE ENCRYPT REQUEST
	// Set the Unique ID of the RSA key to be used for encryption (KMIP Key ID)

	// Set the Unique ID of the RSA key to be used for encryption (KMIP Key ID)
	uniqueID := string(rsaPubKeyId)

	// Set the Cryptographic Parameters (RSA-OAEP with SHA-256)
	// This dictates how the KMIP server performs the RSA encryption.
	cryptographicParameters := kmip.CryptographicParameters{
		// Mandatory for Encrypt using Asymmetric Key
		PaddingMethod: kmip.PaddingMethodOAEP,
		// Use SHA-256 as the Mask Generation Function (MGF) hash
		HashingAlgorithm: kmip.HashingAlgorithmSHA_256,
	}

	// Create the KMIP Request Structure for the Encrypt operation
	request := kmipclient.Request{
		Operation: kmip.OperationEncrypt,
		BatchItem: []kmipclient.BatchItem{
			{
				UniqueIdentifier: uniqueID,
				Data:             aesKeyMaterial,
				// The Cryptographic Parameters apply to the Encrypt operation
				CryptographicParameters: cryptographicParameters,
			},
		},
	}

	// 6. EXECUTE AND PROCESS
	log.Printf("Executing Encrypt operation on CTM using RSA key ID: %s", RSA_KEY_UID)

	ctx := context.Background()
	response, err := c.Do(ctx, request)
	if err != nil {
		log.Fatalf("KMIP Encrypt failed during send: %v", err)
	}

	if len(response.BatchItem) == 0 {
		log.Fatal("KMIP response contained no batch items.")
	}

	batchItem := response.BatchItem[0]
	if batchItem.ResultStatus != kmip.ResultStatusSuccess {
		log.Fatalf("KMIP Operation failed on server. Status: %s, Reason: %s",
			batchItem.ResultStatus.String(), batchItem.ResultReason.String())
	}

	// The Encrypt response payload contains the encrypted data (Ciphertext)
	payload, ok := batchItem.ResponsePayload.(ttlv.EncryptResponse)
	if !ok {
		log.Fatal("Invalid response payload type for Encrypt")
	}

	wrappedKeyBytes := payload.Data.Value()

	// 5. SAVE THE WRAPPED KEY
	if err := os.WriteFile(cfg.AESWrappedFile, wrappedKeyBytes, 0644); err != nil {
		log.Fatalf("Failed to write wrapped key to %s: %v", cfg.AESWrappedFile, err)
	}

	fmt.Println("\n==============================================")
	fmt.Println("✅ AES Key Encrypted Successfully by CTM!")
	fmt.Printf("Encrypted Data (Wrapped Key) Length: %d bytes\n", len(wrappedKeyBytes))
	fmt.Printf("Wrapped key saved to: %s\n", cfg.AESWrappedFile)
	fmt.Println("==============================================")
}

func main() {
	// NOTE: Before running, ensure:
	// 1. Your configuration constants (paths/UIDs) are correct.
	// 2. The RSA key pair (UID: RSA_KEY_UID) is registered in CipherTrust Manager.
	// 3. The input file (aes_gcm_key.bin) exists in the execution directory.

	encryptAesKeyWithRsaKey()
}
