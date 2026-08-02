package fiberauth

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func newMiddlewareApp(secret string) *fiber.App {
	// zero bootTime so all freshly-issued tokens are considered post-boot
	return newMiddlewareAppWithBoot(secret, time.Time{})
}

func newMiddlewareAppWithBoot(secret string, bootTime time.Time) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/protected", AuthMiddleware(secret, bootTime, nil), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "uid": UID(c)})
	})
	app.Get("/admin", AuthMiddleware(secret, bootTime, nil), AdminOnly, func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	return app
}

func issueToken(t *testing.T, secret, uid string, roles []string) string {
	t.Helper()
	tok, err := Issue(secret, uid, roles, 0, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func doAuthed(t *testing.T, app *fiber.App, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	if resp := doAuthed(t, app, "/protected", ""); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	if resp := doAuthed(t, app, "/protected", "this-is-garbage"); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_ValidHeader(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	tok := issueToken(t, testSecret, "uid1", []string{"user"})
	resp := doAuthed(t, app, "/protected", tok)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// UID must be propagated: the handler returns it in the JSON response.
	if !strings.Contains(string(body), "uid1") {
		t.Fatalf("UID not propagated in response: %s", body)
	}
}

// A JWT in the ?token= query param is never accepted: auth is
// header-only, so the token never rides in a URL.
func TestAuthMiddleware_QueryParamRejected(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	tok := issueToken(t, testSecret, "uid1", []string{"user"})
	if resp := doAuthed(t, app, "/protected?token="+tok, ""); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("want 401 (query token must be rejected), got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_PreBootToken(t *testing.T) {
	tok := issueToken(t, testSecret, "uid1", []string{"user"})
	// Boot time set 1s in the future so the just-issued token looks pre-boot.
	app := newMiddlewareAppWithBoot(testSecret, time.Now().Add(time.Second))
	if resp := doAuthed(t, app, "/protected", tok); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("want 401 for pre-boot token, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_PurposeTokenRejected(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	tok, err := IssuePurpose(testSecret, "uid1", "pwreset", 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rejected := ""
	app2 := fiber.New(fiber.Config{DisableStartupMessage: true})
	app2.Get("/protected", AuthMiddleware(testSecret, time.Time{}, func(reason string, c *fiber.Ctx) {
		rejected = reason
	}), func(c *fiber.Ctx) error { return c.SendString("ok") })

	if resp := doAuthed(t, app, "/protected", tok); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("want 401 for purpose token, got %d", resp.StatusCode)
	}
	if resp := doAuthed(t, app2, "/protected", tok); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("want 401 for purpose token, got %d", resp.StatusCode)
	}
	if rejected == "" {
		t.Fatal("onReject callback must fire for a purpose token")
	}
}

func TestAdminOnly_UserRole(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	tok := issueToken(t, testSecret, "uid1", []string{"user"})
	if resp := doAuthed(t, app, "/admin", tok); resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestAdminOnly_AdminRole(t *testing.T) {
	app := newMiddlewareApp(testSecret)
	tok := issueToken(t, testSecret, "uid1", []string{RoleAdmin})
	if resp := doAuthed(t, app, "/admin", tok); resp.StatusCode != fiber.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestTokenVersionMiddleware(t *testing.T) {
	stored := map[string]int64{"uid1": 2}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/v", AuthMiddleware(testSecret, time.Time{}, nil), TokenVersionMiddleware(func(uid string) (int64, bool, error) {
		v, ok := stored[uid]
		return v, ok, nil
	}), func(c *fiber.Ctx) error { return c.SendString("ok") })

	fresh, _ := Issue(testSecret, "uid1", []string{"user"}, 2, time.Hour)
	stale, _ := Issue(testSecret, "uid1", []string{"user"}, 1, time.Hour)
	gone, _ := Issue(testSecret, "ghost", []string{"user"}, 2, time.Hour)

	if resp := doAuthed(t, app, "/v", fresh); resp.StatusCode != fiber.StatusOK {
		t.Fatalf("current-version token: want 200, got %d", resp.StatusCode)
	}
	if resp := doAuthed(t, app, "/v", stale); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("stale-version token: want 401, got %d", resp.StatusCode)
	}
	if resp := doAuthed(t, app, "/v", gone); resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("missing user: want 401, got %d", resp.StatusCode)
	}
}
