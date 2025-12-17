package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Credential represents a single OAuth credential
type Credential struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Scopes       []string  `json:"scopes"`
	TokenURI     string    `json:"token_uri"`
	ProjectID    string    `json:"project_id"`
	FilePath     string    `json:"-"`
	Onboarded    bool      `json:"-"`
	mu           sync.Mutex
}

// CredentialPool manages multiple credentials with round-robin selection
type CredentialPool struct {
	credentials  []*Credential
	currentIndex int
	mu           sync.RWMutex
}

// Global credential pool
var credentialPool *CredentialPool

// LoadCredentialPool scans the credentials directory and loads all credential files
func LoadCredentialPool() *CredentialPool {
	pool := &CredentialPool{
		credentials: make([]*Credential, 0),
	}

	// Ensure credentials directory exists
	if err := os.MkdirAll(CredentialsDir, 0755); err != nil {
		log.Printf("Warning: failed to create credentials directory: %v", err)
		return pool
	}

	// Scan for credential files
	pattern := filepath.Join(CredentialsDir, "cred_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("Warning: failed to glob credential files: %v", err)
		return pool
	}

	for _, file := range files {
		cred := loadCredentialFromFile(file)
		if cred != nil {
			pool.credentials = append(pool.credentials, cred)
			log.Printf("Loaded credential from %s", file)
		}
	}

	return pool
}

// loadCredentialFromFile reads and parses a credential JSON file
func loadCredentialFromFile(filePath string) *Credential {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Warning: failed to read credential file %s: %v", filePath, err)
		return nil
	}

	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		log.Printf("Warning: failed to parse credential file %s: %v", filePath, err)
		return nil
	}

	cred.FilePath = filePath

	// Set defaults if not present
	if cred.ClientID == "" {
		cred.ClientID = ClientID
	}
	if cred.ClientSecret == "" {
		cred.ClientSecret = ClientSecret
	}
	if cred.TokenURI == "" {
		cred.TokenURI = "https://oauth2.googleapis.com/token"
	}

	return &cred
}

// GetNext returns the next credential in round-robin fashion
func (p *CredentialPool) GetNext() *Credential {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.credentials) == 0 {
		return nil
	}

	cred := p.credentials[p.currentIndex]
	p.currentIndex = (p.currentIndex + 1) % len(p.credentials)
	return cred
}

// Reload reloads all credentials from disk
func (p *CredentialPool) Reload() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.credentials = make([]*Credential, 0)
	p.currentIndex = 0

	pattern := filepath.Join(CredentialsDir, "cred_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	for _, file := range files {
		cred := loadCredentialFromFile(file)
		if cred != nil {
			p.credentials = append(p.credentials, cred)
		}
	}
}

// Count returns the number of credentials in the pool
func (p *CredentialPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.credentials)
}

// GetAll returns all credentials (for display purposes)
func (p *CredentialPool) GetAll() []*Credential {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*Credential, len(p.credentials))
	copy(result, p.credentials)
	return result
}

// EnsureValid checks if the token is expired and refreshes if needed
func (c *Credential) EnsureValid() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if token is still valid (with 5 minute buffer)
	if time.Now().Add(5 * time.Minute).Before(c.Expiry) {
		return nil
	}

	log.Printf("Refreshing token for credential %s", c.FilePath)

	// Refresh the token
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"refresh_token": {c.RefreshToken},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	// Update credential
	c.Token = tokenResp.AccessToken
	c.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Save to file
	return c.saveToFile()
}

// saveToFile saves the credential back to its JSON file
func (c *Credential) saveToFile() error {
	data := map[string]interface{}{
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
		"token":         c.Token,
		"refresh_token": c.RefreshToken,
		"expiry":        c.Expiry.Format(time.RFC3339),
		"scopes":        c.Scopes,
		"token_uri":     c.TokenURI,
		"project_id":    c.ProjectID,
	}

	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.FilePath, jsonData, 0600)
}

// IsValid checks if the credential token is currently valid
func (c *Credential) IsValid() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.Expiry)
}

// authenticateUser validates the API access password
// Supports 4 methods (in priority order):
// 1. Query parameter: ?key=password
// 2. x-goog-api-key header
// 3. Bearer token
// 4. HTTP Basic Auth
func authenticateUser(r *http.Request) bool {
	// 1. Query parameter
	if key := r.URL.Query().Get("key"); key != "" {
		return key == GeminiAuthPassword
	}

	// 2. x-goog-api-key header
	if apiKey := r.Header.Get("x-goog-api-key"); apiKey != "" {
		return apiKey == GeminiAuthPassword
	}

	// 3 & 4. Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// 3. Bearer token
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			return token == GeminiAuthPassword
		}

		// 4. HTTP Basic Auth
		if strings.HasPrefix(authHeader, "Basic ") {
			encoded := strings.TrimPrefix(authHeader, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return false
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[1] == GeminiAuthPassword
			}
		}
	}

	return false
}

// generateRandomState generates a random state string for OAuth
func generateRandomState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// exchangeCodeForToken exchanges an authorization code for tokens
func exchangeCodeForToken(code, redirectURI string) (*TokenResponse, error) {
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// discoverProjectID discovers the Cloud AI Companion project ID
func discoverProjectID(accessToken string) (string, error) {
	payload := map[string]interface{}{
		"metadata": getClientMetadata(""),
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", CodeAssistEndpoint+"/v1internal:loadCodeAssist",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", getUserAgent())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}

	if projectID, ok := data["cloudaicompanionProject"].(string); ok {
		return projectID, nil
	}

	return "", nil
}

// onboardUser completes the onboarding process for a credential
func onboardUser(cred *Credential) error {
	if cred.Onboarded && cred.ProjectID != "" {
		return nil
	}

	// Step 1: loadCodeAssist
	loadPayload := map[string]interface{}{
		"cloudaicompanionProject": cred.ProjectID,
		"metadata":                getClientMetadata(cred.ProjectID),
	}

	loadResp, err := postToGoogle(cred, "/v1internal:loadCodeAssist", loadPayload)
	if err != nil {
		return err
	}

	// Get project ID from response if we don't have one
	if cred.ProjectID == "" {
		if projectID, ok := loadResp["cloudaicompanionProject"].(string); ok && projectID != "" {
			cred.ProjectID = projectID
			cred.saveToFile()
		}
	}

	// Check if already has currentTier
	if loadResp["currentTier"] != nil {
		cred.Onboarded = true
		return nil
	}

	// Get default tier
	var tier map[string]interface{}
	if tiers, ok := loadResp["allowedTiers"].([]interface{}); ok {
		for _, t := range tiers {
			if tm, ok := t.(map[string]interface{}); ok {
				if tm["isDefault"] == true {
					tier = tm
					break
				}
			}
		}
	}

	if tier == nil {
		tier = map[string]interface{}{
			"id":                                  "legacy-tier",
			"userDefinedCloudaicompanionProject": true,
		}
	}

	// Step 2: onboardUser (poll until done)
	onboardPayload := map[string]interface{}{
		"tierId":                  tier["id"],
		"cloudaicompanionProject": cred.ProjectID,
		"metadata":                getClientMetadata(cred.ProjectID),
	}

	for i := 0; i < 60; i++ { // Max 5 minutes (60 * 5s)
		onboardResp, err := postToGoogle(cred, "/v1internal:onboardUser", onboardPayload)
		if err != nil {
			return err
		}

		// Try to get project ID from response
		if cred.ProjectID == "" {
			if projectID, ok := onboardResp["cloudaicompanionProject"].(string); ok && projectID != "" {
				cred.ProjectID = projectID
			}
		}

		if onboardResp["done"] == true {
			cred.Onboarded = true
			return nil
		}

		time.Sleep(5 * time.Second)
	}

	return nil
}

// postToGoogle sends a POST request to the Google API
func postToGoogle(cred *Credential, path string, payload map[string]interface{}) (map[string]interface{}, error) {
	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", CodeAssistEndpoint+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cred.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", getUserAgent())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(body, &data)

	return data, nil
}

// saveCredential saves a new credential to a file
func saveCredential(filePath string, tokenResp *TokenResponse, projectID string) error {
	cred := map[string]interface{}{
		"client_id":     ClientID,
		"client_secret": ClientSecret,
		"token":         tokenResp.AccessToken,
		"refresh_token": tokenResp.RefreshToken,
		"expiry":        time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
		"scopes":        Scopes,
		"token_uri":     "https://oauth2.googleapis.com/token",
		"project_id":    projectID,
	}

	jsonData, err := json.MarshalIndent(cred, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, jsonData, 0600)
}

// getNextCredentialIndex returns the next available credential index
func getNextCredentialIndex() int {
	pattern := filepath.Join(CredentialsDir, "cred_*.json")
	files, _ := filepath.Glob(pattern)
	return len(files)
}
