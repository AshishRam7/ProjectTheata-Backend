package main

import (
	"backend/internal/database"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// --- Constants & Global Variables ---
const (
	ADKAgentBaseURL     = "http://localhost:8000"
	ADKAgentAppName     = "agents"
	GoBackendPort       = "8080"
	FrontendURL         = "http://localhost:3000"
)

var (
	httpClient       *http.Client
	googleOAuthConfig *oauth2.Config
	dbService        database.Service
	sseManagerGlobal *SSEManager
)

// --- Structs ---
type SSEEvent struct { Type string; ID string; Payload interface{} }
type Client chan SSEEvent
type sseClientRegistration struct { id string; client Client }
type SSEManager struct {
	clients    map[string]map[Client]bool
	mu         sync.RWMutex
	broadcast  chan SSEEvent
	register   chan sseClientRegistration
	unregister chan sseClientRegistration
}
type ADKCreateSessionPayload struct { State map[string]interface{} `json:"state,omitempty"` }
type ADKNewMessagePart struct { Text string `json:"text,omitempty"` }

// --- FIXED STRUCT ---
type ADKNewMessage struct {
	Role  string              `json:"role"` // <--- THIS IS THE FIX: Added the `json:"role"` tag
	Parts []ADKNewMessagePart `json:"parts"`
}
// --- END OF FIX ---

type ADKRunPayload struct {
	AppName    string        `json:"app_name"`
	UserID     string        `json:"user_id"`
	SessionID  string        `json:"session_id"`
	NewMessage ADKNewMessage `json:"new_message"`
	Stream     bool          `json:"stream,omitempty"`
}

// --- Utility & SSE Functions (Unchanged) ---
func respondWithError(w http.ResponseWriter, code int, message string) {
	log.Printf("Responding with error [%d]: %s", code, message)
	respondWithJSON(w, code, map[string]string{"error": message})
}
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil { log.Printf("Error marshalling JSON response: %v", err); w.WriteHeader(http.StatusInternalServerError); w.Write([]byte(`{"error": "Internal server error"}`)); return }
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
func NewSSEManager() *SSEManager { return &SSEManager{ clients: make(map[string]map[Client]bool), broadcast: make(chan SSEEvent, 100), register: make(chan sseClientRegistration), unregister: make(chan sseClientRegistration) } }
func (m *SSEManager) RunLoop() { /* Implementation unchanged */ }
func (m *SSEManager) Publish(id string, eventType string, payload interface{}) { /* Implementation unchanged */ }


// --- Google OAuth2 Handlers (Unchanged) ---
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	supabaseUserID := r.URL.Query().Get("supabase_user_id")
	if supabaseUserID == "" { respondWithError(w, http.StatusBadRequest, "supabase_user_id query parameter is required"); return }
	url := googleOAuthConfig.AuthCodeURL(supabaseUserID, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	log.Printf("Redirecting user %s to Google for OAuth consent", supabaseUserID)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" { respondWithError(w, http.StatusBadRequest, "Invalid callback: state parameter missing"); return }
	supabaseUserID := state
	if code == "" {
		log.Printf("User %s denied Google OAuth permission.", supabaseUserID)
		http.Redirect(w, r, fmt.Sprintf("%s/app?error=google_auth_denied", FrontendURL), http.StatusTemporaryRedirect)
		return
	}
	token, err := googleOAuthConfig.Exchange(ctx, code)
	if err != nil { respondWithError(w, http.StatusInternalServerError, "Failed to exchange code for token: "+err.Error()); return }
	if err := dbService.SaveGoogleTokens(ctx, supabaseUserID, token); err != nil { respondWithError(w, http.StatusInternalServerError, "Failed to save authentication tokens"); return }
	log.Printf("Successfully obtained and saved Google tokens for user %s", supabaseUserID)
	http.Redirect(w, r, fmt.Sprintf("%s/app?google_auth_success=true", FrontendURL), http.StatusTemporaryRedirect)
}

func handleGoogleAuthStatus(w http.ResponseWriter, r *http.Request) {
	supabaseUserID := r.URL.Query().Get("supabase_user_id")
	if supabaseUserID == "" { respondWithError(w, http.StatusBadRequest, "supabase_user_id query parameter is required"); return }
	token, err := dbService.GetGoogleTokens(r.Context(), supabaseUserID)
	if err != nil { respondWithError(w, http.StatusInternalServerError, "Error checking token status: "+err.Error()); return }
	if token == nil || token.RefreshToken == "" {
		respondWithJSON(w, http.StatusOK, map[string]interface{}{"connected": false, "reason": "not_connected"})
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"connected": true})
}

// --- Token Refresh Logic (Unchanged) ---
func getRefreshedToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	token, err := dbService.GetGoogleTokens(ctx, userID)
	if err != nil { return nil, fmt.Errorf("could not get token from DB: %w", err) }
	if token == nil { return nil, fmt.Errorf("user has not authenticated with Google") }
	tokenSource := googleOAuthConfig.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil { return nil, fmt.Errorf("failed to refresh token: %w", err) }
	if newToken.AccessToken != token.AccessToken {
		log.Printf("Google token for user %s was refreshed. Saving new token to DB.", userID)
		if err := dbService.SaveGoogleTokens(ctx, userID, newToken); err != nil {
			log.Printf("ERROR: Failed to save refreshed token to DB for user %s: %v", userID, err)
		}
	}
	return newToken, nil
}


// --- Task Execution Handler (Unchanged) ---
func handleExecuteTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id,omitempty"`
		Text   string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { respondWithError(w, http.StatusBadRequest, "Invalid task request payload: "+err.Error()); return }
	defer r.Body.Close()

	if req.UserID == "" { respondWithError(w, http.StatusBadRequest, "user_id is required to execute tasks"); return }

	token, err := getRefreshedToken(r.Context(), req.UserID)
	if err != nil {
		log.Printf("Task execution failed for user %s because of token error: %v", req.UserID, err)
		respondWithJSON(w, http.StatusForbidden, map[string]interface{}{ "error": "Google Authentication Error", "message": err.Error(), "needs_reauth": true, })
		return
	}

	tokenStateForADK := map[string]interface{}{ "token": token.AccessToken, "refresh_token": token.RefreshToken, "token_uri": googleOAuthConfig.Endpoint.TokenURL, "client_id": googleOAuthConfig.ClientID, "client_secret": googleOAuthConfig.ClientSecret, "scopes": googleOAuthConfig.Scopes, }
	initialState := map[string]interface{}{ "google_oauth_token": tokenStateForADK, }

	adkSessionIDForTask := fmt.Sprintf("task-%s-%d", req.UserID, time.Now().UnixNano())
	createSessionURL := fmt.Sprintf("%s/apps/%s/users/%s/sessions/%s", ADKAgentBaseURL, ADKAgentAppName, req.UserID, adkSessionIDForTask)
	createPayload := ADKCreateSessionPayload{State: initialState}
	createPayloadBytes, _ := json.Marshal(createPayload)
	createReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, createSessionURL, bytes.NewBuffer(createPayloadBytes))
	createReq.Header.Set("Content-Type", "application/json")

	log.Printf("Creating ADK session %s for user %s with Google token state.", adkSessionIDForTask, req.UserID)
	createResp, err := httpClient.Do(createReq)
	if err != nil || createResp.StatusCode >= 400 {
		errMsg := "Failed to create ADK session for task."
		if err != nil { errMsg += " " + err.Error() } else { body, _ := io.ReadAll(createResp.Body); errMsg += fmt.Sprintf(" Status: %d, Body: %s", createResp.StatusCode, string(body)); createResp.Body.Close() }
		respondWithError(w, http.StatusServiceUnavailable, errMsg)
		return
	}
	createResp.Body.Close()
	log.Printf("ADK session %s created successfully.", adkSessionIDForTask)

	runURL := fmt.Sprintf("%s/run", ADKAgentBaseURL)
	runPayload := ADKRunPayload{ AppName: ADKAgentAppName, UserID: req.UserID, SessionID: adkSessionIDForTask, NewMessage: ADKNewMessage{ Role:  "user", Parts: []ADKNewMessagePart{{Text: req.Text}}, }, Stream: false, }
	runPayloadBytes, _ := json.Marshal(runPayload)
	runReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, runURL, bytes.NewBuffer(runPayloadBytes))
	runReq.Header.Set("Content-Type", "application/json")

	log.Printf("Executing task for user %s in session %s...", req.UserID, adkSessionIDForTask)
	runResp, err := httpClient.Do(runReq)
	if err != nil { respondWithError(w, http.StatusServiceUnavailable, "Error contacting ADK agent for task: "+err.Error()); return }
	defer runResp.Body.Close()

	adkBodyBytes, _ := io.ReadAll(runResp.Body)
	w.Header().Set("Content-Type", runResp.Header.Get("Content-Type"))
	w.WriteHeader(runResp.StatusCode)
	w.Write(adkBodyBytes)
}


// --- Lifecycle & Main Function (Unchanged) ---
func gracefulShutdown(srv *http.Server, done chan bool) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("Shutting down gracefully, press Ctrl+C again to force")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctxShutdown); err != nil { log.Printf("Server forced to shutdown with error: %v", err) }
	log.Println("Server exiting")
	done <- true
}

func main() {
	if err := godotenv.Load(); err != nil { log.Println("No .env file found, reading from environment") }

	httpClient = &http.Client{Timeout: 60 * time.Second}
	dbService = database.New()
	sseManagerGlobal = NewSSEManager()
	go sseManagerGlobal.RunLoop()

	googleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URI"),
		Scopes: []string{ "https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/calendar.events", "https://www.googleapis.com/auth/drive.readonly", },
		Endpoint: google.Endpoint,
	}
	if googleOAuthConfig.ClientID == "" || googleOAuthConfig.ClientSecret == "" || googleOAuthConfig.RedirectURL == "" {
		log.Fatal("FATAL: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI must be set in the environment.")
	}

	rootRouter := chi.NewRouter()
	rootRouter.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	rootRouter.Use(middleware.Logger)

	apiRouter := chi.NewRouter()
	apiRouter.Get("/auth/google/login", handleGoogleLogin)
	apiRouter.Get("/auth/google/callback", handleGoogleCallback)
	apiRouter.Get("/auth/google/status", handleGoogleAuthStatus)
	apiRouter.Post("/tasks/execute", handleExecuteTask)
	
	rootRouter.Mount("/api", apiRouter)
	log.Println("API routes registered under /api")

	finalHttpServer := &http.Server{ Addr: ":" + GoBackendPort, Handler: rootRouter, }

	done := make(chan bool, 1)
	go gracefulShutdown(finalHttpServer, done)

	log.Printf("Go backend server starting on: http://localhost:%s", GoBackendPort)
	err := finalHttpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed { log.Fatalf("Http server error: %s", err) }
	<-done
	log.Println("Graceful shutdown complete.")
}