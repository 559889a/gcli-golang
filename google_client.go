package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

// getUserAgent returns the User-Agent string for requests
func getUserAgent() string {
	system := runtime.GOOS
	arch := runtime.GOARCH
	return fmt.Sprintf("GeminiCLI/%s (%s; %s)", CLIVersion, system, arch)
}

// getPlatformString returns the platform string for client metadata
func getPlatformString() string {
	system := strings.ToUpper(runtime.GOOS)
	arch := strings.ToUpper(runtime.GOARCH)

	switch system {
	case "DARWIN":
		if arch == "ARM64" {
			return "DARWIN_ARM64"
		}
		return "DARWIN_AMD64"
	case "LINUX":
		if arch == "ARM64" {
			return "LINUX_ARM64"
		}
		return "LINUX_AMD64"
	case "WINDOWS":
		return "WINDOWS_AMD64"
	default:
		return "PLATFORM_UNSPECIFIED"
	}
}

// getClientMetadata returns the client metadata for Google API calls
func getClientMetadata(projectID string) map[string]interface{} {
	platform := getPlatformString()
	return map[string]interface{}{
		"ideType":     "IDE_UNSPECIFIED",
		"platform":    platform,
		"pluginType":  "GEMINI",
		"duetProject": projectID,
	}
}

// buildGeminiPayload builds the final payload for Google API
func buildGeminiPayload(intermediate map[string]interface{}, projectID string) map[string]interface{} {
	request := map[string]interface{}{}

	// Copy all non-nil fields
	fields := []string{"contents", "systemInstruction", "generationConfig",
		"safetySettings", "tools", "toolConfig", "cachedContent"}
	for _, field := range fields {
		if v, ok := intermediate[field]; ok && v != nil {
			request[field] = v
		}
	}

	return map[string]interface{}{
		"model":   intermediate["model"],
		"project": projectID,
		"request": request,
	}
}

// sendGeminiRequest sends a request to the Google Code Assist API
func sendGeminiRequest(cred *Credential, payload map[string]interface{}, isStreaming bool) (*http.Response, error) {
	// Build URL
	baseURL := CodeAssistEndpoint + "/v1internal:"
	var reqURL string
	if isStreaming {
		reqURL = baseURL + "streamGenerateContent?alt=sse"
	} else {
		reqURL = baseURL + "generateContent"
	}

	// Build final payload
	finalPayload := buildGeminiPayload(payload, cred.ProjectID)

	jsonData, err := json.Marshal(finalPayload)
	if err != nil {
		return nil, err
	}

	// Create request
	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+cred.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", getUserAgent())

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[网络错误] Gemini API 请求失败: %v", err)
		return nil, err
	}
	return resp, nil
}

// handleNonStreamingResponse processes a non-streaming response from Google API
func handleNonStreamingResponse(resp *http.Response) (map[string]interface{}, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[网络错误] 读取响应失败: %v", err)
		return nil, err
	}

	bodyStr := string(body)

	// Log error responses
	if resp.StatusCode >= 400 {
		log.Printf("[HTTP %d] Google API 错误: %s", resp.StatusCode, bodyStr)
	}

	// Remove possible "data: " prefix (sometimes present even in non-streaming)
	if strings.HasPrefix(bodyStr, "data: ") {
		bodyStr = bodyStr[6:]
	}

	var wrapper map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &wrapper); err != nil {
		return nil, err
	}

	// Extract "response" field if present
	if response, ok := wrapper["response"].(map[string]interface{}); ok {
		return response, nil
	}

	return wrapper, nil
}

// StreamWriter handles writing SSE responses to the client
type StreamWriter struct {
	w          http.ResponseWriter
	flusher    http.Flusher
	model      string
	responseID string
}

// NewStreamWriter creates a new StreamWriter
func NewStreamWriter(w http.ResponseWriter, model string) *StreamWriter {
	flusher, _ := w.(http.Flusher)

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	return &StreamWriter{
		w:          w,
		flusher:    flusher,
		model:      model,
		responseID: "chatcmpl-" + uuid.New().String(),
	}
}

// WriteChunk writes a single chunk to the stream
func (sw *StreamWriter) WriteChunk(chunk map[string]interface{}) {
	openaiChunk := geminiStreamChunkToOpenAI(chunk, sw.model, sw.responseID)
	chunkJSON, err := json.Marshal(openaiChunk)
	if err != nil {
		log.Printf("[错误] 序列化 chunk 失败: %v", err)
		return
	}
	fmt.Fprintf(sw.w, "data: %s\n\n", chunkJSON)
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
}

// WriteDone writes the [DONE] marker
func (sw *StreamWriter) WriteDone() {
	fmt.Fprintf(sw.w, "data: [DONE]\n\n")
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
}

// handleStreamingResponse processes a streaming response from Google API
func handleStreamingResponse(resp *http.Response, w http.ResponseWriter, model string) {
	// Handle error responses
	if resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[网络错误] 读取错误响应失败: %v", err)
			http.Error(w, "Failed to read error response", http.StatusBadGateway)
			return
		}
		log.Printf("[HTTP %d] Google API 错误: %s", resp.StatusCode, string(body))
		http.Error(w, fmt.Sprintf("Google API error: %s", resp.Status), resp.StatusCode)
		return
	}

	sw := NewStreamWriter(w, model)

	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer size for potentially large chunks
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := line[6:] // Remove "data: " prefix

		var wrapper map[string]interface{}
		if err := json.Unmarshal([]byte(data), &wrapper); err != nil {
			continue
		}

		// Extract "response" field if present
		var geminiChunk map[string]interface{}
		if response, ok := wrapper["response"].(map[string]interface{}); ok {
			geminiChunk = response
		} else {
			geminiChunk = wrapper
		}

		sw.WriteChunk(geminiChunk)
	}

	sw.WriteDone()
}
