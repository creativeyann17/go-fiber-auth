package fiberauth

import (
	"strings"
	"time"
)

// LoginRecord is one successful login, kept newest-first on the app's
// user record for the "recent activity" view and new-IP detection.
type LoginRecord struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"userAgent,omitempty"`
	At        time.Time `json:"at"`
}

// AppendLoginRecord prepends a record and caps the history at max
// entries. The user agent is truncated to 120 runes so a hostile UA
// header can't bloat the stored record.
func AppendLoginRecord(history []LoginRecord, ip, ua string, max int) []LoginRecord {
	ip = strings.Clone(ip)
	if runes := []rune(ua); len(runes) > 120 {
		ua = string(runes[:120])
	} else {
		ua = strings.Clone(ua)
	}
	r := LoginRecord{IP: ip, UserAgent: ua, At: time.Now()}
	history = append([]LoginRecord{r}, history...)
	if len(history) > max {
		history = history[:max]
	}
	return history
}

// IsNewIP reports whether ip has never appeared in history. False on
// empty history: a first login isn't an alert.
func IsNewIP(ip string, history []LoginRecord) bool {
	if len(history) == 0 {
		return false
	}
	for _, r := range history {
		if r.IP == ip {
			return false
		}
	}
	return true
}
