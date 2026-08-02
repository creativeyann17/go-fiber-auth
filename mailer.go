package fiberauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Mailer sends transactional email via Resend's HTTP API
// (https://resend.com/docs/api-reference/emails/send-email). A plain
// HTTP call rather than the official SDK: one endpoint, one request
// shape, not worth a new dependency.
//
// APIKey-gated: an empty APIKey makes Send a no-op returning nil, so
// email flows degrade gracefully in dev/CI instead of erroring. Apps
// check Enabled() to log the code instead of sending.
type Mailer struct {
	APIKey     string
	From       string
	HTTPClient *http.Client
	Endpoint   string // overridden in tests, defaults to Resend's API
}

func NewMailer(apiKey, from string) *Mailer {
	return &Mailer{
		APIKey:     apiKey,
		From:       from,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Endpoint:   "https://api.resend.com/emails",
	}
}

func (m *Mailer) Enabled() bool { return m.APIKey != "" }

type mailerSendReq struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

// Send emails to via Resend, HTML body. No-op (nil error) when APIKey
// is empty.
func (m *Mailer) Send(to, subject, html string) error {
	if m.APIKey == "" {
		return nil
	}
	body, err := json.Marshal(mailerSendReq{From: m.From, To: []string{to}, Subject: subject, HTML: html})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, m.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mailer: resend responded %d", resp.StatusCode)
	}
	return nil
}
