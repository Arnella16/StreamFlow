package main

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

func main() {
	// --------------------------
// Start Gateway
// --------------------------
app := fiber.New()

// CORS for frontend
app.Use(cors.New(cors.Config{
    AllowOrigins:     "http://127.0.0.1:8081,http://localhost:5173",
    AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    AllowHeaders:     "Content-Type,Authorization",
    AllowCredentials: true,
}))

// ---------------------------------------------
// Proxy ALL non-API routes to Vite Dev Server
// ---------------------------------------------
app.Use(func(c *fiber.Ctx) error {
    path := c.Path()

    // Allow API routes to continue normally
    if strings.HasPrefix(path, "/auth/api") ||
        strings.HasPrefix(path, "/upload/api") ||
        strings.HasPrefix(path, "/social/api") ||
        strings.HasPrefix(path, "/search/api") ||
        strings.HasPrefix(path, "/hls") {

        return c.Next()
    }

    // Everything else goes to Vite dev server
    target := "http://localhost:5173" + c.OriginalURL()
    return proxy.Do(c, target)
})

// Proxy helper
forward := func(prefix, target string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        trimmed := strings.TrimPrefix(c.OriginalURL(), prefix)
        return proxy.Do(c, target+trimmed)
    }
}

// --------------------------
// API proxy routes
// --------------------------
app.All("/auth/api/*", forward("/auth/api", "http://127.0.0.1:3000"))
app.All("/upload/api/*", forward("/upload/api", "http://127.0.0.1:3001"))
app.All("/social/api/*", forward("/social/api", "http://127.0.0.1:3002"))
app.All("/search/api/*", forward("/search/api", "http://127.0.0.1:8080"))
app.All("/hls/*", forward("/hls", "http://127.0.0.1:8083"))

// --------------------------
// Start server
// --------------------------
log.Println("🚀 Gateway running at http://127.0.0.1:8081")
log.Fatal(app.Listen(":8081"))

}