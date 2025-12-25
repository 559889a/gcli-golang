package main

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// OpenAI Request Structures
type OpenAIRequest struct {
	Model            string                 `json:"model"`
	Messages         []OpenAIMessage        `json:"messages"`
	Stream           bool                   `json:"stream"`
	Temperature      *float64               `json:"temperature,omitempty"`
	TopP             *float64               `json:"top_p,omitempty"`
	MaxTokens        *int                   `json:"max_tokens,omitempty"`
	Stop             interface{}            `json:"stop,omitempty"`
	FrequencyPenalty *float64               `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64               `json:"presence_penalty,omitempty"`
	N                *int                   `json:"n,omitempty"`
	Seed             *int                   `json:"seed,omitempty"`
	ResponseFormat   map[string]interface{} `json:"response_format,omitempty"`
	ReasoningEffort  *string                `json:"reasoning_effort,omitempty"`
}

type OpenAIMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// extractText extracts text content from OpenAI message content
// Content can be a string or an array of content parts
func extractText(content interface{}) string {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		var texts []string
		for _, part := range v {
			if p, ok := part.(map[string]interface{}); ok {
				if p["type"] == "text" {
					if text, ok := p["text"].(string); ok {
						texts = append(texts, text)
					}
				}
			}
		}
		return strings.Join(texts, "")
	}
	return ""
}

// getBaseModelName extracts the base model name by removing suffixes
func getBaseModelName(modelName string) string {
	suffixes := []string{"-high", "-medium", "-low", "-minimal", "-search"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(modelName, suffix) {
			return modelName[:len(modelName)-len(suffix)]
		}
	}
	return modelName
}

// isSearchModel checks if the model is a search variant
func isSearchModel(modelName string) bool {
	return strings.Contains(modelName, "-search")
}

// getThinkingLevel extracts the thinking level from model name
func getThinkingLevel(modelName string) string {
	levels := []string{"minimal", "low", "medium", "high"}
	for _, level := range levels {
		if strings.HasSuffix(modelName, "-"+level) {
			return level
		}
	}
	return ""
}

// openaiRequestToGemini converts an OpenAI format request to Gemini format
func openaiRequestToGemini(request *OpenAIRequest) map[string]interface{} {
	// Collect system messages
	var systemParts []string
	var contents []map[string]interface{}

	for _, msg := range request.Messages {
		if msg.Role == "system" {
			text := extractText(msg.Content)
			if text != "" {
				systemParts = append(systemParts, text)
			}
		} else {
			// Map role: user -> user, assistant -> model
			role := msg.Role
			if role == "assistant" {
				role = "model"
			}

			text := extractText(msg.Content)
			if text != "" {
				contents = append(contents, map[string]interface{}{
					"role": role,
					"parts": []map[string]string{
						{"text": text},
					},
				})
			}
		}
	}

	// Build generation config
	generationConfig := map[string]interface{}{
		"topK":            64,
		"maxOutputTokens": 65535,
	}

	// Temperature and TopP passthrough
	if request.Temperature != nil {
		generationConfig["temperature"] = *request.Temperature
	}
	if request.TopP != nil {
		generationConfig["topP"] = *request.TopP
	}

	// Stop sequences
	if request.Stop != nil {
		switch v := request.Stop.(type) {
		case string:
			generationConfig["stopSequences"] = []string{v}
		case []interface{}:
			var seqs []string
			for _, s := range v {
				if str, ok := s.(string); ok {
					seqs = append(seqs, str)
				}
			}
			generationConfig["stopSequences"] = seqs
		}
	}

	// Candidate count (n)
	if request.N != nil {
		generationConfig["candidateCount"] = *request.N
	}

	// Seed
	if request.Seed != nil {
		generationConfig["seed"] = *request.Seed
	}

	// Response format
	if request.ResponseFormat != nil {
		if request.ResponseFormat["type"] == "json_object" {
			generationConfig["responseMimeType"] = "application/json"
		}
	}

	// Thinking level
	thinkingLevel := getThinkingLevel(request.Model)
	if thinkingLevel == "" && request.ReasoningEffort != nil {
		thinkingLevel = *request.ReasoningEffort
	}
	if thinkingLevel != "" {
		generationConfig["thinkingConfig"] = map[string]interface{}{
			"thinkingLevel":   thinkingLevel,
			"includeThoughts": true,
		}
	}

	// Build payload
	payload := map[string]interface{}{
		"model":            getBaseModelName(request.Model),
		"contents":         contents,
		"generationConfig": generationConfig,
		"safetySettings":   DefaultSafetySettings,
	}

	// System instruction
	if len(systemParts) > 0 {
		payload["systemInstruction"] = map[string]interface{}{
			"parts": []map[string]string{
				{"text": strings.Join(systemParts, "\n\n")},
			},
		}
	}

	// Search model -> add googleSearch tool
	if isSearchModel(request.Model) {
		payload["tools"] = []map[string]interface{}{
			{"googleSearch": map[string]interface{}{}},
		}
	}

	return payload
}

// mapFinishReason converts Gemini finish reason to OpenAI format
func mapFinishReason(geminiReason interface{}) interface{} {
	reason, ok := geminiReason.(string)
	if !ok {
		return nil
	}
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION":
		return "content_filter"
	default:
		return nil
	}
}

// geminiResponseToOpenAI converts a Gemini response to OpenAI format (non-streaming)
func geminiResponseToOpenAI(gemini map[string]interface{}, model string) map[string]interface{} {
	var choices []map[string]interface{}

	candidates, _ := gemini["candidates"].([]interface{})
	for i, c := range candidates {
		candidate, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		content, _ := candidate["content"].(map[string]interface{})

		// Role mapping: model -> assistant
		role := "assistant"
		if r, ok := content["role"].(string); ok && r == "model" {
			role = "assistant"
		}

		// Separate thinking content and actual content
		parts, _ := content["parts"].([]interface{})
		var contentParts []string
		var reasoningContent string

		for _, p := range parts {
			part, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			text, _ := part["text"].(string)
			if thought, ok := part["thought"].(bool); ok && thought {
				reasoningContent += text
			} else {
				contentParts = append(contentParts, text)
			}
		}

		// Build message
		message := map[string]interface{}{
			"role":    role,
			"content": strings.Join(contentParts, "\n\n"),
		}
		if reasoningContent != "" {
			message["reasoning_content"] = reasoningContent
		}

		// Get index
		index := i
		if idx, ok := candidate["index"].(float64); ok {
			index = int(idx)
		}

		choices = append(choices, map[string]interface{}{
			"index":         index,
			"message":       message,
			"finish_reason": mapFinishReason(candidate["finishReason"]),
		})
	}

	return map[string]interface{}{
		"id":      "chatcmpl-" + uuid.New().String(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": choices,
	}
}

// geminiStreamChunkToOpenAI converts a Gemini stream chunk to OpenAI format
func geminiStreamChunkToOpenAI(chunk map[string]interface{}, model, responseID string) map[string]interface{} {
	var choices []map[string]interface{}

	candidates, _ := chunk["candidates"].([]interface{})
	for i, c := range candidates {
		candidate, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		content, _ := candidate["content"].(map[string]interface{})

		// Separate thinking content and actual content
		parts, _ := content["parts"].([]interface{})
		var contentParts []string
		var reasoningContent string

		for _, p := range parts {
			part, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			text, _ := part["text"].(string)
			if thought, ok := part["thought"].(bool); ok && thought {
				reasoningContent += text
			} else {
				contentParts = append(contentParts, text)
			}
		}

		// Build delta
		delta := map[string]interface{}{}
		if len(contentParts) > 0 {
			delta["content"] = strings.Join(contentParts, "\n\n")
		}
		if reasoningContent != "" {
			delta["reasoning_content"] = reasoningContent
		}

		// Get index
		index := i
		if idx, ok := candidate["index"].(float64); ok {
			index = int(idx)
		}

		choices = append(choices, map[string]interface{}{
			"index":         index,
			"delta":         delta,
			"finish_reason": mapFinishReason(candidate["finishReason"]),
		})
	}

	return map[string]interface{}{
		"id":      responseID,
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": choices,
	}
}

// createOpenAIErrorResponse creates an OpenAI-compatible error response
func createOpenAIErrorResponse(statusCode int, upstreamError map[string]interface{}) map[string]interface{} {
	errMsg := "Unknown error from upstream API"
	errType := "api_error"

	if upstreamError != nil {
		// Try to extract error info from upstream response
		if errObj, ok := upstreamError["error"].(map[string]interface{}); ok {
			if msg, ok := errObj["message"].(string); ok {
				errMsg = msg
			}
			if status, ok := errObj["status"].(string); ok {
				errType = status
			}
			if code, ok := errObj["code"].(string); ok && errType == "api_error" {
				errType = code
			}
		}
	}

	return map[string]interface{}{
		"error": map[string]interface{}{
			"message": errMsg,
			"type":    errType,
			"code":    statusCode,
		},
	}
}
