package main

import (
	"os"
)

// API Endpoint
const CodeAssistEndpoint = "https://cloudcode-pa.googleapis.com"

// OAuth Configuration
const (
	CLIVersion = "0.21.1"
)

var (
	ClientID     = getEnv("GOOGLE_CLIENT_ID", "")
	ClientSecret = getEnv("GOOGLE_CLIENT_SECRET", "")
)

var Scopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

// Safety Settings - All set to BLOCK_NONE
var DefaultSafetySettings = []map[string]string{
	{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_IMAGE_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_IMAGE_HARASSMENT", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_IMAGE_HATE", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_IMAGE_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_UNSPECIFIED", "threshold": "BLOCK_NONE"},
	{"category": "HARM_CATEGORY_JAILBREAK", "threshold": "BLOCK_NONE"},
}

// Base Models
var BaseModels = []string{
	"gemini-3-pro-preview",
	"gemini-3-flash-preview",
}

// Thinking Levels for each model
var ThinkingLevels = map[string][]string{
	"gemini-3-pro-preview":   {"high", "low"},
	"gemini-3-flash-preview": {"minimal", "low", "medium", "high"},
}

// Environment Variables
var (
	Port               = getEnv("PORT", "8888")
	Host               = getEnv("HOST", "0.0.0.0")
	GeminiAuthPassword = getEnv("GEMINI_AUTH_PASSWORD", "123456")
	CredentialsDir     = getEnv("CREDENTIALS_DIR", "./credentials")
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetAllModels generates all model variants
func GetAllModels() []string {
	var models []string

	for _, base := range BaseModels {
		// Base model
		models = append(models, base)

		// Search variant
		models = append(models, base+"-search")

		// Thinking level variants
		if levels, ok := ThinkingLevels[base]; ok {
			for _, level := range levels {
				models = append(models, base+"-"+level)
			}
		}
	}

	return models
}
