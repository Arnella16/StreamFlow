package main

import (
	"fmt"
	"log"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:5173, http://127.0.0.1:5173, http://localhost:8081",
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		ExposeHeaders:    "Content-Length",
		AllowCredentials: true,
	}))

	// Simple endpoint to receive logs from browser
	app.Get("/log", func(c *fiber.Ctx) error {
		msg := c.Query("msg", "")
		if msg != "" {
			log.Printf("Browser log: %s", msg)
		}
		return c.SendStatus(204)
	})

	port := 8083
	fmt.Printf("Server running at http://localhost:%d\n", port)
	log.Fatal(app.Listen(fmt.Sprintf(":%d", port)))
}
