package main

import (
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "video service healthy"})
	})

	// Add video upload, processing, etc. endpoints here

	app.Listen(":4000") // Use a different port for each service
}
