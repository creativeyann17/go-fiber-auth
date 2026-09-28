package fiberauth

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// Checks the serialized header: MaxAge -1 alone writes no Max-Age/Expires
// in fasthttp, leaving an empty cookie in the browser instead of deleting it.
func TestExpiredCookiesDeleteInBrowser(t *testing.T) {
	for name, ck := range map[string]*fiber.Cookie{
		"refresh": ExpiredRefreshCookie("rt", "/api/auth"),
		"device":  ExpiredDeviceCookie("dev"),
	} {
		app := fiber.New()
		app.Get("/", func(c *fiber.Ctx) error {
			c.Cookie(ck)
			return nil
		})
		resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
		if err != nil {
			t.Fatal(err)
		}
		h := resp.Header.Get("Set-Cookie")
		if !strings.Contains(h, "expires=Thu, 01 Jan 1970") {
			t.Fatalf("%s: Set-Cookie %q has no past expires, browser keeps the cookie", name, h)
		}
	}
}
