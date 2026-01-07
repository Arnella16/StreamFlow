package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// Helper function to read Env Vars
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Printf("INFO: %s not set, defaulting to %s", key, fallback)
	return fallback
}

func main() {
	app := fiber.New()

	// --- CORS for your frontend ---
	// Read the allowed origins from an environment variable
	corsOrigins := getEnv("CORS_ALLOW_ORIGINS", "http://localhost:5173,http://98.70.25.253,,http://98.70.25.253:5173,http://98.70.25.253:8081")

	app.Use(cors.New(cors.Config{
		AllowOrigins:     corsOrigins,
		AllowMethods:     "GET,OPTIONS", // Playback is GET-only
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowCredentials: true,
	}))

	// --- THIS IS THE CRITICAL LOGIC ---
	// This is the path *inside the container* where the shared volume will be.
	uploadDir := "/app/uploads"

	// This route serves the master playlist (e.g., /hls/my-video_hls/index.m3u8)
	// and all the video segments (e.g., /hls/my-video_hls/index0.ts)
	app.Static("/hls", uploadDir)

	// This route serves the original MP4 file (e.g., /uploads/test.mp4)
	app.Static("/uploads", uploadDir)
	// --- END OF CRITICAL LOGIC ---

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Your /log endpoint
	app.Get("/log", func(c *fiber.Ctx) error {
		msg := c.Query("msg", "")
		if msg != "" {
			log.Printf("Browser log: %s", msg)
		}
		return c.SendStatus(204)
	})

	port := 8083
	fmt.Printf("🚀 Playback service running at http://98.70.25.253:%d\n", port)

	// Ensure the directory exists (it will be the mount point for the volume)
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Printf("Warning: Could not create %s: %v", uploadDir, err)
	}

	log.Fatal(app.Listen(fmt.Sprintf(":%d", port)))

}
