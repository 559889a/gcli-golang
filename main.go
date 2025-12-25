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

	// Admin login
	mux.HandleFunc("GET /config/login", handleLoginPage)
	mux.HandleFunc("POST /config/login", handleLogin)
	mux.HandleFunc("GET /config/logout", handleLogout)

	// Credential config frontend (admin auth required)
	mux.HandleFunc("GET /config", withAdminAuth(handleConfigPage))
	mux.HandleFunc("GET /config/oauth/start", withAdminAuth(handleOAuthStart))
	mux.HandleFunc("GET /config/oauth/callback", handleOAuthCallback) // OAuth callback doesn't need auth
	mux.HandleFunc("DELETE /config/credential", withAdminAuth(handleDeleteCredential))
	mux.HandleFunc("POST /config/credential", withAdminAuth(handleAddCredential))

	// OpenAI compatible endpoints (auth required)
	mux.HandleFunc("GET /v1/models", withAuth(handleListModels))
	mux.HandleFunc("POST /v1/chat/completions", withAuth(handleChatCompletions))

	return mux
}

// withAuth is an authentication middleware for API endpoints
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

// withAdminAuth is an authentication middleware for admin pages
func withAdminAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdminAuthenticated(r) {
			http.Redirect(w, r, "/config/login", http.StatusFound)
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
		geminiResp, statusCode, err := handleNonStreamingResponse(resp)
		if err != nil {
			log.Printf("Failed to parse response: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(createOpenAIErrorResponse(http.StatusInternalServerError, nil))
			return
		}

		// Check if upstream returned an error
		if statusCode >= 400 {
			errorResp := createOpenAIErrorResponse(statusCode, geminiResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(errorResp)
			return
		}

		openaiResp := geminiResponseToOpenAI(geminiResp, request.Model)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(openaiResp)
	}
}

// Login page HTML template
const loginPageHTML = `<!DOCTYPE html>
<html>
<head>
    <title>geminicli2api 登录</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .login-box { border: 1px solid #ccc; padding: 30px; border-radius: 10px; background: #f9f9f9; }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; }
        input { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #45a049; }
        .error { color: red; text-align: center; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>管理员登录</h1>
        {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
        <form method="POST" action="/config/login">
            <div class="form-group">
                <label>用户名</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>`

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
    <button class="add-btn" onclick="toggleManualForm()" style="background: #2196F3; margin-left: 10px;">手动填入凭证</button>
    <button class="logout-btn" onclick="logout()" style="background: #666; margin-left: 10px;">退出登录</button>

    <div id="manualForm" style="display: none; margin-top: 20px;">
        <h3>手动填入凭证 JSON</h3>
        <p class="info">粘贴完整的凭证 JSON（包含 client_id, client_secret, token, refresh_token 等字段）</p>
        <textarea id="credentialJson" style="width: 100%; height: 300px; font-family: monospace; font-size: 12px; padding: 10px; border: 1px solid #ccc; border-radius: 5px;" placeholder='{
    "client_id": "xxx.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxx",
    "token": "ya29.xxx",
    "refresh_token": "1//xxx",
    "expiry": "2025-12-25T12:00:00+08:00",
    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
    "token_uri": "https://oauth2.googleapis.com/token",
    "project_id": "your-project-id"
}'></textarea>
        <button class="add-btn" onclick="saveCredential()" style="margin-top: 10px;">保存凭证</button>
    </div>

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
        function toggleManualForm() {
            var form = document.getElementById('manualForm');
            form.style.display = form.style.display === 'none' ? 'block' : 'none';
        }
        function saveCredential() {
            var json = document.getElementById('credentialJson').value;
            try {
                JSON.parse(json);
            } catch (e) {
                alert('JSON 格式错误: ' + e.message);
                return;
            }
            fetch('/config/credential', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: json
            }).then(resp => {
                if (resp.ok) {
                    location.reload();
                } else {
                    resp.text().then(text => alert('保存失败: ' + text));
                }
            }).catch(err => alert('请求失败: ' + err));
        }
        function logout() {
            window.location.href = '/config/logout';
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

// LoginPageData represents data for the login page template
type LoginPageData struct {
	Error string
}

// handleLoginPage renders the login page
func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to config page
	if isAdminAuthenticated(r) {
		http.Redirect(w, r, "/config", http.StatusFound)
		return
	}

	tmpl, err := template.New("login").Parse(loginPageHTML)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, LoginPageData{})
}

// handleLogin processes the login form submission
func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == AdminUsername && password == AdminPassword {
		sessionID := createAdminSession()
		setSessionCookie(w, sessionID)
		log.Printf("Admin login successful from %s", r.RemoteAddr)
		http.Redirect(w, r, "/config", http.StatusFound)
		return
	}

	log.Printf("Admin login failed from %s (username: %s)", r.RemoteAddr, username)

	tmpl, err := template.New("login").Parse(loginPageHTML)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, LoginPageData{Error: "用户名或密码错误"})
}

// handleLogout logs out the admin user
func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionFromRequest(r)
	if sessionID != "" {
		deleteAdminSession(sessionID)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/config/login", http.StatusFound)
}

// handleAddCredential handles manually adding a credential via JSON
func handleAddCredential(w http.ResponseWriter, r *http.Request) {
	var cred map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	requiredFields := []string{"token", "refresh_token"}
	for _, field := range requiredFields {
		if _, ok := cred[field]; !ok {
			http.Error(w, "Missing required field: "+field, http.StatusBadRequest)
			return
		}
	}

	// Set defaults for optional fields
	if _, ok := cred["client_id"]; !ok {
		cred["client_id"] = ClientID
	}
	if _, ok := cred["client_secret"]; !ok {
		cred["client_secret"] = ClientSecret
	}
	if _, ok := cred["token_uri"]; !ok {
		cred["token_uri"] = "https://oauth2.googleapis.com/token"
	}
	if _, ok := cred["scopes"]; !ok {
		cred["scopes"] = Scopes
	}

	// Generate file path
	credIndex := getNextCredentialIndex()
	filePath := filepath.Join(CredentialsDir, fmt.Sprintf("cred_%d.json", credIndex))

	// Save to file
	jsonData, err := json.MarshalIndent(cred, "", "    ")
	if err != nil {
		http.Error(w, "Failed to marshal JSON: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		http.Error(w, "Failed to save credential: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Manual credential saved to %s", filePath)

	// Reload credential pool
	credentialPool.Reload()

	// Try to onboard the new credential
	for _, c := range credentialPool.GetAll() {
		if c.FilePath == filePath {
			if err := c.EnsureValid(); err != nil {
				log.Printf("Warning: new credential validation failed: %v", err)
			}
			if err := onboardUser(c); err != nil {
				log.Printf("Warning: new credential onboarding failed: %v", err)
			}
			break
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Credential saved successfully"))
}
