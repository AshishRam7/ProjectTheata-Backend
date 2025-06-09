package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
	"github.com/lib/pq" // Required for handling Postgres TEXT[] type
)

// UserGoogleToken represents the structure of the user_google_tokens table.
type UserGoogleToken struct {
	SupabaseUserID        string
	EncryptedAccessToken  string
	EncryptedRefreshToken sql.NullString // Use sql.NullString for nullable TEXT fields
	TokenExpiry           sql.NullTime   // Use sql.NullTime for nullable TIMESTAMPTZ fields
	Scopes                []string       // Stored as TEXT[] in Postgres
}

// ChatLine represents a row fetched from chat_line, potentially with user handle
type ChatLine struct {
	ID         int64
	ChatID     int
	UserID     int
	UserHandle string
	LineText   string
	CreatedAt  time.Time
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
	// New methods for Google tokens
	SaveOrUpdateUserGoogleToken(ctx context.Context, token UserGoogleToken) error
	GetUserGoogleToken(ctx context.Context, supabaseUserID string) (*UserGoogleToken, error)
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

	// For local development, sslmode=disable is often used. For production, use 'require'.
	sslMode := "require"
	if os.Getenv("DB_SSL_MODE") == "disable" {
		sslMode = "disable"
	}

	connStr := fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s?sslmode=%s&search_path=%s",
		username,
		url.QueryEscape(password),
		host,
		port,
		database,
		sslMode,
		schema,
	)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}

	log.Println("Database connection prepared. Assuming schema is managed.")

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

// SaveOrUpdateUserGoogleToken saves or updates a user's Google OAuth tokens.
func (s *service) SaveOrUpdateUserGoogleToken(ctx context.Context, token UserGoogleToken) error {
	query := `
		INSERT INTO user_google_tokens (user_id, encrypted_access_token, encrypted_refresh_token, token_expiry, scopes)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			encrypted_access_token = EXCLUDED.encrypted_access_token,
			-- Only update the refresh token if a new one is provided (not null and not empty)
			encrypted_refresh_token = COALESCE(NULLIF(EXCLUDED.encrypted_refresh_token, ''), user_google_tokens.encrypted_refresh_token),
			token_expiry = EXCLUDED.token_expiry,
			scopes = EXCLUDED.scopes,
			updated_at = NOW();
	`
	// Use pq.Array to handle the string slice for the 'scopes' column which is a TEXT[] array in Postgres.
	_, err := s.db.ExecContext(ctx, query, token.SupabaseUserID, token.EncryptedAccessToken, token.EncryptedRefreshToken, token.TokenExpiry, pq.Array(token.Scopes))
	if err != nil {
		return fmt.Errorf("failed to save/update google tokens for user %s: %w", token.SupabaseUserID, err)
	}
	log.Printf("Successfully saved/updated Google tokens for user_id: %s", token.SupabaseUserID)
	return nil
}

// GetUserGoogleToken retrieves a user's stored Google OAuth tokens.
func (s *service) GetUserGoogleToken(ctx context.Context, supabaseUserID string) (*UserGoogleToken, error) {
	query := `
		SELECT user_id, encrypted_access_token, encrypted_refresh_token, token_expiry, scopes
		FROM user_google_tokens
		WHERE user_id = $1;
	`
	token := &UserGoogleToken{}
	var scopes pq.StringArray // Use pq.StringArray to scan TEXT[] from Postgres

	err := s.db.QueryRowContext(ctx, query, supabaseUserID).Scan(
		&token.SupabaseUserID,
		&token.EncryptedAccessToken,
		&token.EncryptedRefreshToken,
		&token.TokenExpiry,
		&scopes,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil if no token found, this is not an application error.
		}
		return nil, fmt.Errorf("failed to get google tokens for user %s: %w", supabaseUserID, err)
	}

	token.Scopes = scopes // Assign the scanned scopes to the struct field
	return token, nil
}

// --- Other database methods (unchanged) ---

func (s *service) Close() error {
	if s.db != nil {
		log.Printf("Disconnecting from database: %s", database)
		return s.db.Close()
	}
	log.Println("Database connection already closed or never opened.")
	return nil
}

func (s *service) EnsureChatExists(ctx context.Context, chatID int) error {
	query := `INSERT INTO chat (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`
	_, err := s.db.ExecContext(ctx, query, chatID)
	if err != nil {
		return fmt.Errorf("failed to ensure chat exists (id %d): %w", chatID, err)
	}
	return nil
}

func (s *service) GetOrCreateChatUserByHandle(ctx context.Context, handle string) (int, error) {
	var userID int
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback is a no-op if the transaction has been committed.
	selectQuery := `SELECT id FROM chat_user WHERE handle = $1 FOR UPDATE`
	err = tx.QueryRowContext(ctx, selectQuery, handle).Scan(&userID)
	if err == nil {
		if errCommit := tx.Commit(); errCommit != nil {
			return 0, fmt.Errorf("failed to commit transaction after finding user: %w", errCommit)
		}
		return userID, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		insertQuery := `INSERT INTO chat_user (handle) VALUES ($1) RETURNING id`
		errInsert := tx.QueryRowContext(ctx, insertQuery, handle).Scan(&userID)
		if errInsert != nil {
			return 0, fmt.Errorf("failed to insert new chat user '%s': %w", handle, errInsert)
		}
		if errCommit := tx.Commit(); errCommit != nil {
			return 0, fmt.Errorf("failed to commit transaction after inserting user: %w", errCommit)
		}
		return userID, nil
	}
	return 0, fmt.Errorf("failed to query chat user '%s': %w", handle, err)
}

func (s *service) SaveChatLine(ctx context.Context, chatID int, userID int, text string, timestamp time.Time) error {
	query := `INSERT INTO chat_line (chat_id, user_id, line_text, created_at) VALUES ($1, $2, $3, $4)`
	_, err := s.db.ExecContext(ctx, query, chatID, userID, text, timestamp)
	if err != nil {
		return fmt.Errorf("failed to insert chat line: %w", err)
	}
	return nil
}

func (s *service) GetTotalChatLength(ctx context.Context, chatID int) (int, error) {
	var totalLength int
	query := `SELECT COALESCE(SUM(LENGTH(line_text)), 0) FROM chat_line WHERE chat_id = $1`
	err := s.db.QueryRowContext(ctx, query, chatID).Scan(&totalLength)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
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
	if err != nil {
		return nil, fmt.Errorf("failed to query chat history for chat_id %d: %w", chatID, err)
	}
	defer rows.Close()
	var history []ChatLine
	for rows.Next() {
		var line ChatLine
		err := rows.Scan(&line.ID, &line.ChatID, &line.UserID, &line.UserHandle, &line.LineText, &line.CreatedAt)
		if err != nil {
			log.Printf("Error scanning chat line row for chat_id %d: %v", chatID, err)
			continue
		}
		history = append(history, line)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over chat history rows for chat_id %d: %w", chatID, err)
	}
	return history, nil
}

func (s *service) UpdateChatSummary(ctx context.Context, chatID int, summary string) error {
	query := `UPDATE chat SET summary = $1 WHERE id = $2`
	result, err := s.db.ExecContext(ctx, query, summary, chatID)
	if err != nil {
		return fmt.Errorf("failed to update summary for chat_id %d: %w", chatID, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Could not determine rows affected for chat summary update (chat_id %d): %v", chatID, err)
	}
	if rowsAffected == 0 {
		log.Printf("WARN: UpdateChatSummary affected 0 rows for chat_id %d. Does the chat exist?", chatID)
	}
	return nil
}

func (s *service) GetAllChatLinesText(ctx context.Context, chatID int) (string, error) {
	query := `SELECT line_text FROM chat_line WHERE chat_id = $1 ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, chatID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("failed to query chat lines for chat_id %d: %w", chatID, err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var lineText string
		if err := rows.Scan(&lineText); err != nil {
			return "", fmt.Errorf("failed to scan chat line text for chat_id %d: %w", chatID, err)
		}
		lines = append(lines, lineText)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("error iterating over chat line rows for chat_id %d: %w", chatID, err)
	}
	return strings.Join(lines, "\n"), nil
}