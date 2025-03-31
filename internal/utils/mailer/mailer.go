package mailer

import (
	config "bulbasaur/pkg/config"

	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type EmailRequest struct {
	Email string                 `json:"email"`
	Type  string                 `json:"type"`
	Data  map[string]interface{} `json:"data"`
}

type Mailer interface {
	SendEmail(ctx context.Context, emailReq EmailRequest) error
}

type mailer struct {
	cfg *config.Config
}

func NewMailer(cfg *config.Config) Mailer {
	return &mailer{
		cfg: cfg,
	}
}

func (m *mailer) SendEmail(ctx context.Context, emailReq EmailRequest) error {
	mailerURL := fmt.Sprintf("%s%s", m.cfg.Mailer.Domain, m.cfg.Mailer.Endpoint)

	jsonData, err := json.Marshal(emailReq)
	if err != nil {
		return fmt.Errorf("failed to marshal email request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", mailerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to send email: received status code %d", resp.StatusCode)
	}

	return nil
}
