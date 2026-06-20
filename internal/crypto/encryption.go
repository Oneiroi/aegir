package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

// EncryptionManager handles data encryption and key management
type EncryptionManager struct {
	config     config.Encryption
	logger     *logging.Logger
	masterKey  []byte
	keyRing    map[string]*EncryptionKey
	currentKey *EncryptionKey
}

// EncryptionKey represents an encryption key with metadata
type EncryptionKey struct {
	ID        string    `json:"id"`
	Key       []byte    `json:"-"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
	Version   int       `json:"version"`
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Data      string `json:"data"`
	Nonce     string `json:"nonce"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Timestamp time.Time `json:"timestamp"`
}

// KeyRotationStatus represents the status of key rotation
type KeyRotationStatus struct {
	LastRotation    time.Time `json:"last_rotation"`
	NextRotation    time.Time `json:"next_rotation"`
	CurrentKeyID    string    `json:"current_key_id"`
	ActiveKeys      int       `json:"active_keys"`
	RotationPolicy  string    `json:"rotation_policy"`
}

// New creates a new encryption manager
func NewEncryptionManager(config config.Encryption, logger *logging.Logger) (*EncryptionManager, error) {
	em := &EncryptionManager{
		config:  config,
		logger:  logger,
		keyRing: make(map[string]*EncryptionKey),
	}

	// Generate or load master key
	if err := em.initializeMasterKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize master key: %w", err)
	}

	// Generate initial encryption key
	if err := em.rotateKey(); err != nil {
		return nil, fmt.Errorf("failed to generate initial encryption key: %w", err)
	}

	logger.Info("Encryption manager initialized successfully")
	return em, nil
}

// Encrypt encrypts data using AES-256-GCM
func (em *EncryptionManager) Encrypt(plaintext string) (*EncryptedData, error) {
	if em.currentKey == nil {
		return nil, fmt.Errorf("no encryption key available")
	}

	// Convert plaintext to bytes
	data := []byte(plaintext)

	// Create cipher
	block, err := aes.NewCipher(em.currentKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	encrypted := &EncryptedData{
		Data:      base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		KeyID:     em.currentKey.ID,
		Algorithm: em.config.Algorithm,
		Timestamp: time.Now(),
	}

	em.logger.Debug("Data encrypted successfully", "key_id", em.currentKey.ID)
	return encrypted, nil
}

// Decrypt decrypts data using the appropriate key
func (em *EncryptionManager) Decrypt(encryptedData *EncryptedData) (string, error) {
	// Get the encryption key
	key, exists := em.keyRing[encryptedData.KeyID]
	if !exists {
		return "", fmt.Errorf("encryption key not found: %s", encryptedData.KeyID)
	}

	// Decode the encrypted data
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData.Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Decode the nonce
	nonce, err := base64.StdEncoding.DecodeString(encryptedData.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	em.logger.Debug("Data decrypted successfully", "key_id", key.ID)
	return string(plaintext), nil
}

// RotateKey generates a new encryption key and marks it as current
func (em *EncryptionManager) RotateKey() error {
	return em.rotateKey()
}

// rotateKey generates a new encryption key
func (em *EncryptionManager) rotateKey() error {
	keyID := em.generateKeyID()
	keySize := em.config.KeySize / 8 // Convert bits to bytes

	// Generate random key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create encryption key
	encKey := &EncryptionKey{
		ID:        keyID,
		Key:       key,
		Algorithm: em.config.Algorithm,
		KeySize:   em.config.KeySize,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(0, 0, em.config.KeyRotation),
		Active:    true,
		Version:   len(em.keyRing) + 1,
	}

	// Deactivate old keys if necessary
	for _, oldKey := range em.keyRing {
		oldKey.Active = false
	}

	// Add new key to keyring
	em.keyRing[keyID] = encKey
	em.currentKey = encKey

	em.logger.Info("Encryption key rotated", "key_id", keyID, "algorithm", em.config.Algorithm)

	// Log security event
	em.logKeyRotationEvent(keyID)

	return nil
}

// GetKeyRotationStatus returns the current key rotation status
func (em *EncryptionManager) GetKeyRotationStatus() *KeyRotationStatus {
	var lastRotation time.Time
	activeKeys := 0

	if em.currentKey != nil {
		lastRotation = em.currentKey.CreatedAt
	}

	for _, key := range em.keyRing {
		if key.Active {
			activeKeys++
		}
	}

	nextRotation := lastRotation.AddDate(0, 0, em.config.KeyRotation)

	return &KeyRotationStatus{
		LastRotation:   lastRotation,
		NextRotation:   nextRotation,
		CurrentKeyID:   em.getCurrentKeyID(),
		ActiveKeys:     activeKeys,
		RotationPolicy: fmt.Sprintf("Every %d days", em.config.KeyRotation),
	}
}

// CheckKeyRotation checks if key rotation is needed
func (em *EncryptionManager) CheckKeyRotation() bool {
	if em.currentKey == nil {
		return true
	}

	return time.Now().After(em.currentKey.ExpiresAt)
}

// EncryptSensitiveData encrypts sensitive data with additional context
func (em *EncryptionManager) EncryptSensitiveData(data string, dataType string) (*EncryptedData, error) {
	encrypted, err := em.Encrypt(data)
	if err != nil {
		return nil, err
	}

	// Log encryption event for sensitive data
	em.logEncryptionEvent(dataType, "encrypt")

	return encrypted, nil
}

// DecryptSensitiveData decrypts sensitive data with additional context
func (em *EncryptionManager) DecryptSensitiveData(encrypted *EncryptedData, dataType string) (string, error) {
	decrypted, err := em.Decrypt(encrypted)
	if err != nil {
		return "", err
	}

	// Log decryption event for sensitive data
	em.logEncryptionEvent(dataType, "decrypt")

	return decrypted, nil
}

// initializeMasterKey initializes or loads the master key
func (em *EncryptionManager) initializeMasterKey() error {
	// In production, this would load from a secure key management service
	// For now, we'll generate a deterministic key from a secret
	masterSecret := "aegir-master-secret-2024"
	hash := sha256.Sum256([]byte(masterSecret))
	em.masterKey = hash[:]

	return nil
}

// generateKeyID generates a unique key identifier
func (em *EncryptionManager) generateKeyID() string {
	timestamp := time.Now().Unix()
	return fmt.Sprintf("key_%d_%s", timestamp, em.generateRandomString(8))
}

// generateRandomString generates a random string of specified length
func (em *EncryptionManager) generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// getCurrentKeyID returns the current key ID
func (em *EncryptionManager) getCurrentKeyID() string {
	if em.currentKey != nil {
		return em.currentKey.ID
	}
	return ""
}

// logKeyRotationEvent logs key rotation events
func (em *EncryptionManager) logKeyRotationEvent(keyID string) {
	event := &logging.SecurityEvent{
		Type:      "key_rotation",
		Severity:  "info",
		Message:   "Encryption key rotated",
		Timestamp: time.Now(),
		Details: map[string]string{
			"key_id":    keyID,
			"algorithm": em.config.Algorithm,
			"key_size":  fmt.Sprintf("%d", em.config.KeySize),
		},
	}

	em.logger.LogSecurityEvent(event)
}

// logEncryptionEvent logs encryption/decryption events
func (em *EncryptionManager) logEncryptionEvent(dataType, operation string) {
	event := &logging.SecurityEvent{
		Type:      "encryption_operation",
		Severity:  "info",
		Message:   fmt.Sprintf("Data %s operation performed", operation),
		Timestamp: time.Now(),
		Details: map[string]string{
			"operation": operation,
			"data_type": dataType,
			"key_id":    em.getCurrentKeyID(),
		},
	}

	em.logger.LogSecurityEvent(event)
}