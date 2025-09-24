package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// check if port is free
func waitForPortRelease(port string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Listen("tcp", ":"+port)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("port %s did not free up in time", port)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	// ---------- CLEAN PORT BEFORE START ----------
	fmt.Printf("Cleaning any process using port %s...\n", port)
	kill := exec.Command("fuser", "-k", port+"/tcp")
	kill.Stdout = os.Stdout
	kill.Stderr = os.Stderr
	_ = kill.Run() // ignore error if nothing is running

	// Wait for the port to actually release
	if err := waitForPortRelease(port, 3*time.Second); err != nil {
		log.Fatalf("Port %s is still busy: %v", port, err)
	}

	// ---------- FIBER APP ----------
	app := fiber.New()

	// CORS with explicit origin (safe for credentials)
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:5173,http://localhost:3000,http://localhost:3001",
		AllowMethods:     "GET,POST,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		panic(err)
	}

	// ---------- ROUTES ----------
	app.Get("/upload", func(c *fiber.Ctx) error {
		return c.SendFile("./public/index.html")
	})

	app.Options("/upload", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	app.Post("/upload", func(c *fiber.Ctx) error {
		file, err := c.FormFile("video")
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "No video file uploaded")
		}
		savePath := filepath.Join(uploadDir, file.Filename)
		if err := c.SaveFile(file, savePath); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to save video")
		}
		return c.JSON(fiber.Map{
			"message": "Video uploaded successfully",
			"path":    "/uploads/" + file.Filename,
		})
	})

	app.Static("/static", "./public")
	app.Static("/uploads", "./uploads")

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	app.Use(func(c *fiber.Ctx) error {
		return c.Status(404).SendString("Not Found")
	})

	// ---------- GRACEFUL SHUTDOWN ----------
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nShutting down upload service...")
		app.Shutdown()
	}()

	// ---------- START SERVER ----------
	fmt.Printf("Upload service running at http://localhost:%s\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
