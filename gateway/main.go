package main

import (
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

// Helper function to get env var or use a default (for local testing)
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Printf("INFO: %s not set, defaulting to %s", key, fallback)
	return fallback
}

// Proxy helper function (your code, unchanged)
func forward(prefix, target string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		trimmed := strings.TrimPrefix(c.OriginalURL(), prefix)
		return proxy.Do(c, target+trimmed)
	}
}

func main() {
	app := fiber.New()

	// --- 1. CORS for your frontend ---
	// This is still needed for your real frontend URL
	app.Use(cors.New(cors.Config{
		AllowOrigins:     os.Getenv("CORS_ALLOW_ORIGINS"), // Read from Env Var
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// --- 2. API Proxy Routes ---
	// Read all target service URLs from environment variables
	authTarget := getEnv("AUTH_SERVICE_URL", "http://98.70.25.253:3000")
	uploadTarget := getEnv("UPLOAD_SERVICE_URL", "http://98.70.25.253:3001")
	socialTarget := getEnv("SOCIAL_SERVICE_URL", "http://98.70.25.253:3002")
	searchTarget := getEnv("SEARCH_SERVICE_URL", "http://98.70.25.253:8080")
	hlsTarget := getEnv("HLS_SERVICE_URL", "http://98.70.25.253:8083")

	log.Println("--- Gateway API Proxy Targets ---")
	log.Printf("Auth    -> %s", authTarget)
	log.Printf("Upload  -> %s", uploadTarget)
	log.Printf("Social  -> %s", socialTarget)
	log.Printf("Search  -> %s", searchTarget)
	log.Printf("HLS     -> %s", hlsTarget)
	log.Println("---------------------------------")

	// Create an /api group for all API routes
	api := app.Group("/api")

	// Map the API prefixes to their targets
	api.All("/auth/*", forward("/api/auth", authTarget+"/api/auth"))
	api.All("/upload/*", forward("/api/upload", uploadTarget+"/api/upload"))
	api.All("/social/*", forward("/api/social", socialTarget+"/api/social"))
	api.All("/search/*", forward("/api/search", searchTarget+"/api/search"))
	api.All("/hls/*", forward("/api/hls", hlsTarget+"/api/hls"))

	// --- 3. Static File Server (The Production Fix) ---
	// This replaces your Vite proxy.
	// It serves the 'dist' folder that your Dockerfile built.
	// The path './client/dist' matches the Dockerfile's final COPY step.
	app.Static("/", "./client/dist")

	// --- 4. SPA Catch-All ---
	// This is critical for React/Vite. It ensures that if a user
	// reloads the page at /my-profile, the server sends index.html
	// and lets React Router handle it.
	app.Get("/*", func(c *fiber.Ctx) error {
		// Send the main index.html file for any non-API, non-file request
		return c.SendFile("./client/dist/index.html")
	})

	// --- 5. Start Server ---
	port := getEnv("PORT", "8081")
	log.Printf("🚀 Gateway running at http://98.70.25.253:%s", port)
	log.Fatal(app.Listen(":" + port))
}
