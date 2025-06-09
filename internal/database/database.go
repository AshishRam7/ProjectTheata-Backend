package database

import (
	//"backend/migrations"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	//"strconv"
	"strings" // Import strings package
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
	//"github.com/pressly/goose/v3"
	_ "gotest.tools/v3/fs"
	"golang.org/x/oauth2"
)

// ChatLine represents a row fetched from chat_line, potentially with user handle
type ChatLine struct {
	ID         int64
	ChatID     int
	UserID     int
	UserHandle string // Added for GetChatHistory
	LineText   string
	CreatedAt  time.Time
}

// GoogleToken represents a stored Google OAuth token.
type GoogleToken struct {
	SupabaseUserID string
	oauth2.Token   // Embed the oauth2.Token struct
}

// Service represents a service that interacts with a database.
type Service interface {
	Health() map[string]string
	Close() error
	GetOrCreateChatUserByHandle(ctx context.Context, handle string) (int, error)
	SaveChatLine(ctx context.Context, chatID int, userID int, text string, timestamp time.Time) error
	EnsureChatExists(ctx context.Context, chatID int) error
	GetTotalChatLength(ctx context.Context, chatID int) (int, error)
	GetChatHistory(ctx context.Context, chatID int) ([]ChatLine, error)
	UpdateChatSummary(ctx context.Context, chatID int, summary string) error
	GetAllChatLinesText(ctx context.Context, chatid int) (string, error)
	SaveGoogleTokens(ctx context.Context, userID string, token *oauth2.Token) error
	GetGoogleTokens(ctx context.Context, userID string) (*oauth2.Token, error)
}

type service struct {
	db *sql.DB
}

var (
	database   = os.Getenv("BLUEPRINT_DB_DATABASE")
	password   = os.Getenv("BLUEPRINT_DB_PASSWORD")
	username   = os.Getenv("BLUEPRINT_DB_USERNAME")
	port       = os.Getenv("BLUEPRINT_DB_PORT")
	host       = os.Getenv("BLUEPRINT_DB_HOST")
	schema     = os.Getenv("BLUEPRINT_DB_SCHEMA")
	dbInstance *service
)

// New initializes the database service.
func New() Service {
	if dbInstance != nil {
		return dbInstance
	}

	connStr := fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s?sslmode=require&search_path=%s",
		username,
		url.QueryEscape(password),
		host,
		port,
		database,
		url.QueryEscape(schema),
	)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// This check is fine, but we will not run migrations if the tables already exist.
	// We'll assume the user has a schema and our code should adapt to it.
	log.Println("Database connection prepared. Skipping automatic migration to use existing schema.")

	dbInstance = &service{db: db}
	return dbInstance
}

// Health checks the database connection status.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	err := s.db.PingContext(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Printf("db down: %v", err)
		return stats
	}

	stats["status"] = "up"
	stats["message"] = "It's healthy"
	return stats
}

// SaveGoogleTokens saves or updates a user's Google OAuth tokens matching the user's schema.
func (s *service) SaveGoogleTokens(ctx context.Context, userID string, token *oauth2.Token) error {
	// THIS QUERY IS NOW FIXED TO MATCH YOUR SCHEMA FROM THE IMAGE
	query := `
		INSERT INTO user_google_tokens (user_id, encrypted_access_token, encrypted_refresh_token, token_expiry)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET
			encrypted_access_token = EXCLUDED.encrypted_access_token,
			-- Only update the refresh token if a new one is provided
			encrypted_refresh_token = COALESCE(NULLIF(EXCLUDED.encrypted_refresh_token, ''), user_google_tokens.encrypted_refresh_token),
			token_expiry = EXCLUDED.token_expiry,
			updated_at = NOW();
	`
	_, err := s.db.ExecContext(ctx, query, userID, token.AccessToken, token.RefreshToken, token.Expiry)
	if err != nil {
		return fmt.Errorf("failed to save google tokens for user %s: %w", userID, err)
	}
	log.Printf("Successfully saved Google tokens for user_id: %s", userID)
	return nil
}

// GetGoogleTokens retrieves a user's stored Google OAuth tokens matching the user's schema.
func (s *service) GetGoogleTokens(ctx context.Context, userID string) (*oauth2.Token, error) {
	// THIS QUERY IS NOW FIXED TO MATCH YOUR SCHEMA FROM THE IMAGE
	query := `
		SELECT encrypted_access_token, encrypted_refresh_token, token_expiry
		FROM user_google_tokens
		WHERE user_id = $1;
	`
	token := &oauth2.Token{}
	// Note: We are not selecting token_type as it's not in your schema.
	// The oauth2.Token object can function without it.
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&token.AccessToken, &token.RefreshToken, &token.Expiry)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil if no token found, not an error
		}
		return nil, fmt.Errorf("failed to get google tokens for user %s: %w", userID, err)
	}
	return token, nil
}

// --- Other database methods remain unchanged ---
// I'm omitting them for brevity, but they are the same as the previous correct version.
func (s *service) EnsureChatExists(ctx context.Context, chatID int) error {
	query := `INSERT INTO chat (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`
	_, err := s.db.ExecContext(ctx, query, chatID)
	if err != nil { return fmt.Errorf("failed to ensure chat exists (id %d): %w", chatID, err) }
	return nil
}
func (s *service) GetOrCreateChatUserByHandle(ctx context.Context, handle string) (int, error) {
	var userID int
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return 0, fmt.Errorf("failed to begin transaction: %w", err) }
	defer tx.Rollback()
	selectQuery := `SELECT id FROM chat_user WHERE handle = $1 FOR UPDATE`
	err = tx.QueryRowContext(ctx, selectQuery, handle).Scan(&userID)
	if err == nil {
		if errCommit := tx.Commit(); errCommit != nil { return 0, fmt.Errorf("failed to commit transaction after finding user: %w", errCommit) }
		return userID, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		insertQuery := `INSERT INTO chat_user (handle) VALUES ($1) RETURNING id`
		errInsert := tx.QueryRowContext(ctx, insertQuery, handle).Scan(&userID)
		if errInsert != nil { return 0, fmt.Errorf("failed to insert new chat user '%s': %w", handle, errInsert) }
		if errCommit := tx.Commit(); errCommit != nil { return 0, fmt.Errorf("failed to commit transaction after inserting user: %w", errCommit) }
		return userID, nil
	}
	return 0, fmt.Errorf("failed to query chat user '%s': %w", handle, err)
}
func (s *service) SaveChatLine(ctx context.Context, chatID int, userID int, text string, timestamp time.Time) error {
	query := `INSERT INTO chat_line (chat_id, user_id, line_text, created_at) VALUES ($1, $2, $3, $4)`
	_, err := s.db.ExecContext(ctx, query, chatID, userID, text, timestamp)
	if err != nil { return fmt.Errorf("failed to insert chat line: %w", err) }
	return nil
}
func (s *service) GetTotalChatLength(ctx context.Context, chatID int) (int, error) {
	var totalLength int
	query := `SELECT COALESCE(SUM(LENGTH(line_text)), 0) FROM chat_line WHERE chat_id = $1`
	err := s.db.QueryRowContext(ctx, query, chatID).Scan(&totalLength)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return 0, nil }
		return 0, fmt.Errorf("failed to query total chat length for chat_id %d: %w", chatID, err)
	}
	return totalLength, nil
}
func (s *service) GetChatHistory(ctx context.Context, chatID int) ([]ChatLine, error) {
	query := `
		SELECT cl.id, cl.chat_id, cl.user_id, cu.handle, cl.line_text, cl.created_at
		FROM chat_line cl JOIN chat_user cu ON cl.user_id = cu.id
		WHERE cl.chat_id = $1 ORDER BY cl.created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, chatID)
	if err != nil { return nil, fmt.Errorf("failed to query chat history for chat_id %d: %w", chatID, err) }
	defer rows.Close()
	var history []ChatLine
	for rows.Next() {
		var line ChatLine
		err := rows.Scan(&line.ID, &line.ChatID, &line.UserID, &line.UserHandle, &line.LineText, &line.CreatedAt)
		if err != nil { log.Printf("Error scanning chat line row for chat_id %d: %v", chatID, err); continue }
		history = append(history, line)
	}
	if err = rows.Err(); err != nil { return nil, fmt.Errorf("error iterating over chat history rows for chat_id %d: %w", chatID, err) }
	return history, nil
}
func (s *service) UpdateChatSummary(ctx context.Context, chatID int, summary string) error {
	query := `UPDATE chat SET summary = $1 WHERE id = $2`
	result, err := s.db.ExecContext(ctx, query, summary, chatID)
	if err != nil { return fmt.Errorf("failed to update summary for chat_id %d: %w", chatID, err) }
	rowsAffected, err := result.RowsAffected()
	if err != nil { log.Printf("Could not determine rows affected for chat summary update (chat_id %d): %v", chatID, err) }
	if rowsAffected == 0 { log.Printf("WARN: UpdateChatSummary affected 0 rows for chat_id %d. Does the chat exist?", chatID) }
	return nil
}
func (s *service) GetAllChatLinesText(ctx context.Context, chatID int) (string, error) {
	query := `SELECT line_text FROM chat_line WHERE chat_id = $1 ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, chatID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return "", nil }
		return "", fmt.Errorf("failed to query chat lines for chat_id %d: %w", chatID, err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var lineText string
		if err := rows.Scan(&lineText); err != nil { return "", fmt.Errorf("failed to scan chat line text for chat_id %d: %w", chatID, err) }
		lines = append(lines, lineText)
	}
	if err := rows.Err(); err != nil { return "", fmt.Errorf("error iterating over chat line rows for chat_id %d: %w", chatID, err) }
	return strings.Join(lines, "\n"), nil
}
func (s *service) Close() error {
	if s.db != nil {
		log.Printf("Disconnecting from database: %s", database)
		return s.db.Close()
	}
	log.Println("Database connection already closed or never opened.")
	return nil
}
// Dummy migration functions since we are not running them anymore
func MigrateFs(db *sql.DB, migrationFS fs.FS, dir string) error { return nil }
func MigrateStatus(db *sql.DB, dir string) error { return nil }