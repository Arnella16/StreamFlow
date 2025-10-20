package main

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

func main() {
	app := fiber.New()

	// --------------------------
	// CORS for all requests
	// --------------------------
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:8081,http://localhost:3000", // Or restrict to your frontend: "http://localhost:8081"
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type, Authorization",
		AllowCredentials: true,
	}))

	// --------------------------
	// Serve React frontend (Vite build)
	// --------------------------
	frontendDir := "../client/dist"
	app.Static("/", frontendDir)

	// Fallback for React Router
	app.Use(func(c *fiber.Ctx) error {
		path := c.Path()
		if strings.HasPrefix(path, "/auth/api") ||
			strings.HasPrefix(path, "/upload/api") ||
			strings.HasPrefix(path, "/social/api") {
			return c.Next()
		}
		return c.SendFile(frontendDir + "/index.html")
	})

	// --------------------------
	// Helper to forward API routes to microservices
	// --------------------------
	forward := func(prefix, target string) fiber.Handler {
		return func(c *fiber.Ctx) error {
			trimmed := strings.TrimPrefix(c.OriginalURL(), prefix)
			return proxy.Do(c, target+trimmed)
		}
	}

	// --------------------------
	// API Proxy routes
	// --------------------------
	app.All("/auth/api/*", forward("/auth/api", "http://127.0.0.1:3000"))
	app.All("/upload/api/*", forward("/upload/api", "http://127.0.0.1:3001"))
	app.All("/social/api/*", forward("/social/api", "http://127.0.0.1:3002"))

	// --------------------------
	// Start Gateway server
	// --------------------------
	log.Println("Gateway running on port 8081")
	log.Fatal(app.Listen(":8081"))
}
