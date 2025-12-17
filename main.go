package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	// 1. Load credential pool
	credentialPool = LoadCredentialPool()
	log.Printf("Loaded %d credentials", credentialPool.Count())

	// 2. Onboard all credentials
	for _, cred := range credentialPool.GetAll() {
		if err := cred.EnsureValid(); err != nil {
			log.Printf("Warning: credential %s refresh failed: %v", cred.FilePath, err)
			continue
		}
		if err := onboardUser(cred); err != nil {
			log.Printf("Warning: credential %s onboarding failed: %v", cred.FilePath, err)
		}
	}

	// 3. Setup routes
	mux := setupRoutes()

	// 4. Start server
	addr := Host + ":" + Port
	log.Printf("Starting geminicli2api server on %s", addr)
	log.Printf("Config page: http://localhost:%s/config", Port)
	log.Printf("API password: %s", GeminiAuthPassword)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// setupRoutes configures all HTTP routes
func setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Handle OPTIONS for all paths (CORS preflight)
	mux.HandleFunc("OPTIONS /{path...}", handleCORS)

	// Basic endpoints (no auth required)
	mux.HandleFunc("GET /", handleRoot)
	mux.HandleFunc("GET /health", handleHealth)

	// Credential config frontend (no API auth)
	mux.HandleFunc("GET /config", handleConfigPage)
	mux.HandleFunc("GET /config/oauth/start", handleOAuthStart)
	mux.HandleFunc("GET /config/oauth/callback", handleOAuthCallback)
	mux.HandleFunc("DELETE /config/credential", handleDeleteCredential)

	// OpenAI compatible endpoints (auth required)
	mux.HandleFunc("GET /v1/models", withAuth(handleListModels))
	mux.HandleFunc("POST /v1/chat/completions", withAuth(handleChatCompletions))

	return mux
}

// withAuth is an authentication middleware
func withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addCORSHeaders(w)

		if !authenticateUser(r) {
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

// handleCORS handles CORS preflight requests
func handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.WriteHeader(http.StatusOK)
}

// addCORSHeaders adds CORS headers to response
func addCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// handleRoot handles the root endpoint
func handleRoot(w http.ResponseWriter, r *http.Request) {
	addCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"service": "geminicli2api",
		"version": CLIVersion,
		"status":  "running",
	})
}

// handleHealth handles health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request) {
	addCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "healthy",
		"credentials": credentialPool.Count(),
	})
}

// handleListModels returns the list of available models
func handleListModels(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	models := GetAllModels()

	var data []map[string]interface{}
	for _, model := range models {
		data = append(data, map[string]interface{}{
			"id":       model,
			"object":   "model",
			"created":  time.Now().Unix(),
			"owned_by": "google",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": "list",
		"data":   data,
	})
}

// handleChatCompletions handles chat completion requests
func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)

	// Parse request
	var request OpenAIRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error parsing request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Request: model=%s, stream=%v, messages=%d", request.Model, request.Stream, len(request.Messages))

	// Get credential
	cred := credentialPool.GetNext()
	if cred == nil {
		log.Printf("Error: No credentials available")
		http.Error(w, "No credentials available", http.StatusServiceUnavailable)
		return
	}

	log.Printf("Using credential: %s", cred.FilePath)

	// Ensure credential is valid
	if err := cred.EnsureValid(); err != nil {
		log.Printf("Failed to refresh credential: %v", err)
		http.Error(w, "Credential error", http.StatusInternalServerError)
		return
	}

	// Ensure onboarded
	if err := onboardUser(cred); err != nil {
		log.Printf("Failed to onboard: %v", err)
	}

	// Convert request
	geminiPayload := openaiRequestToGemini(&request)

	// Send to Google API
	resp, err := sendGeminiRequest(cred, geminiPayload, request.Stream)
	if err != nil {
		log.Printf("Failed to send request to Google: %v", err)
		http.Error(w, "Failed to contact Google API", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("Google API: %s", resp.Status)

	// Handle response
	if request.Stream {
		handleStreamingResponse(resp, w, request.Model)
	} else {
		geminiResp, err := handleNonStreamingResponse(resp)
		if err != nil {
			log.Printf("Failed to parse response: %v", err)
			http.Error(w, "Failed to parse response", http.StatusInternalServerError)
			return
		}

		openaiResp := geminiResponseToOpenAI(geminiResp, request.Model)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openaiResp)
	}
}

// Config page HTML template
const configPageHTML = `<!DOCTYPE html>
<html>
<head>
    <title>geminicli2api 凭证配置</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .cred-card { border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .cred-card.valid { border-color: green; background: #f0fff0; }
        .cred-card.expired { border-color: red; background: #fff0f0; }
        button { padding: 10px 20px; margin: 5px; cursor: pointer; border-radius: 5px; }
        .add-btn { background: #4CAF50; color: white; border: none; }
        .add-btn:hover { background: #45a049; }
        .delete-btn { background: #f44336; color: white; border: none; }
        .delete-btn:hover { background: #da190b; }
        h1 { color: #333; }
        h2 { color: #666; margin-top: 30px; }
        .info { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <h1>geminicli2api 凭证配置</h1>
    <p class="info">管理您的 Google OAuth 凭证</p>

    <h2>当前凭证 (共 {{.Count}} 个)</h2>
    {{if eq .Count 0}}
    <p class="info">暂无凭证，请点击下方按钮添加。</p>
    {{else}}
    {{range .Credentials}}
    <div class="cred-card {{if .Valid}}valid{{else}}expired{{end}}">
        <p><strong>文件:</strong> {{.FilePath}}</p>
        <p><strong>Project ID:</strong> {{.ProjectID}}</p>
        <p><strong>状态:</strong> {{if .Valid}}有效{{else}}已过期{{end}}</p>
        <p><strong>过期时间:</strong> {{.Expiry}}</p>
        <button class="delete-btn" onclick="deleteCred('{{.FilePath}}')">删除</button>
    </div>
    {{end}}
    {{end}}

    <h2>添加新凭证</h2>
    <button class="add-btn" onclick="startOAuth()">开始 OAuth 登录</button>

    <script>
        function startOAuth() {
            window.location.href = '/config/oauth/start';
        }
        function deleteCred(path) {
            if (confirm('确定删除此凭证?')) {
                fetch('/config/credential?path=' + encodeURIComponent(path), {method: 'DELETE'})
                    .then(() => location.reload());
            }
        }
    </script>
</body>
</html>`

// CredentialView represents credential data for template rendering
type CredentialView struct {
	FilePath  string
	ProjectID string
	Valid     bool
	Expiry    string
}

// ConfigPageData represents data for the config page template
type ConfigPageData struct {
	Count       int
	Credentials []CredentialView
}

// handleConfigPage renders the credential configuration page
func handleConfigPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("config").Parse(configPageHTML)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	var views []CredentialView
	for _, cred := range credentialPool.GetAll() {
		views = append(views, CredentialView{
			FilePath:  cred.FilePath,
			ProjectID: cred.ProjectID,
			Valid:     cred.IsValid(),
			Expiry:    cred.Expiry.Format(time.RFC3339),
		})
	}

	data := ConfigPageData{
		Count:       len(views),
		Credentials: views,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// handleOAuthStart initiates the OAuth flow
func handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	state := generateRandomState()

	redirectURI := fmt.Sprintf("http://localhost:%s/config/oauth/callback", Port)

	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&access_type=offline&prompt=consent&state=%s",
		ClientID,
		url.QueryEscape(redirectURI),
		url.QueryEscape(strings.Join(Scopes, " ")),
		state,
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthCallback handles the OAuth callback
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	redirectURI := fmt.Sprintf("http://localhost:%s/config/oauth/callback", Port)

	// Exchange code for token
	tokenResp, err := exchangeCodeForToken(code, redirectURI)
	if err != nil {
		log.Printf("Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Discover project ID
	projectID, err := discoverProjectID(tokenResp.AccessToken)
	if err != nil {
		log.Printf("Failed to discover project ID: %v", err)
	}

	// Save credential
	credIndex := getNextCredentialIndex()
	filePath := filepath.Join(CredentialsDir, fmt.Sprintf("cred_%d.json", credIndex))

	if err := saveCredential(filePath, tokenResp, projectID); err != nil {
		log.Printf("Failed to save credential: %v", err)
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}

	log.Printf("New credential saved to %s", filePath)

	// Reload credential pool
	credentialPool.Reload()

	// Onboard the new credential
	for _, cred := range credentialPool.GetAll() {
		if cred.FilePath == filePath {
			if err := onboardUser(cred); err != nil {
				log.Printf("Failed to onboard new credential: %v", err)
			}
			break
		}
	}

	// Redirect back to config page
	http.Redirect(w, r, "/config", http.StatusFound)
}

// handleDeleteCredential deletes a credential file
func handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "Missing path parameter", http.StatusBadRequest)
		return
	}

	// Security check: ensure path is within credentials directory
	absPath, _ := filepath.Abs(path)
	absCredDir, _ := filepath.Abs(CredentialsDir)
	if !strings.HasPrefix(absPath, absCredDir) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if err := os.Remove(path); err != nil {
		log.Printf("Failed to delete credential: %v", err)
		http.Error(w, "Failed to delete credential", http.StatusInternalServerError)
		return
	}

	log.Printf("Deleted credential: %s", path)
	credentialPool.Reload()

	w.WriteHeader(http.StatusOK)
}
