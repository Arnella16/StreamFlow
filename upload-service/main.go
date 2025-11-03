package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/go-resty/resty/v2"

)

// waitForPortRelease ensures the port is free before listening
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

// chunkVideo uses FFmpeg to split uploaded video into HLS segments
func chunkVideo(inputPath string) error {
	base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	outDir := filepath.Join("uploads", base+"_hls")

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	cmd := exec.Command("ffmpeg",
		"-i", inputPath,
		"-profile:v", "baseline",
		"-level", "3.0",
		"-start_number", "0",
		"-hls_time", "10",
		"-hls_list_size", "0",
		"-f", "hls",
		filepath.Join(outDir, "index.m3u8"),
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	port := "3001"

	// Clean any process using this port
	fmt.Printf("Cleaning any process using port %s...\n", port)
	_ = exec.Command("fuser", "-k", port+"/tcp").Run()

	if err := waitForPortRelease(port, 3*time.Second); err != nil {
		log.Fatalf("Port %s is still busy: %v", port, err)
	}

	app := fiber.New()
	client := resty.New()


	// Enable CORS for your frontend (5173 for Vite, etc.)
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
		AllowMethods:     "GET,POST,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	// ----------- ROUTES -----------

	// Serve static files
	app.Static("/uploads", "./uploads")
	app.Static("/static", "./public")

	// Upload directly to root (POST /)
	app.Post("/", func(c *fiber.Ctx) error {
		file, err := c.FormFile("video")
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "No video file uploaded")
		}

		savePath := filepath.Join(uploadDir, file.Filename)
		if err := c.SaveFile(file, savePath); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to save video")
		}

		// Notify the socials service
		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]string{
				"id":       file.Filename,
				"title":    file.Filename,
				"thumbnail": "https://picsum.photos/seed/" + file.Filename + "/640/360",
				"path": "http://localhost:3001/uploads/" + file.Filename,
			}).Post("http://localhost:3002/init")

		if err != nil {
			log.Println("⚠️ Failed to notify socials service:", err)
		} else if resp.IsError() {
			log.Println("⚠️ Socials service responded with error:", resp.String())
		} else {
			log.Println("✅ Social record created:", resp.String())
		}


		// Run FFmpeg chunking asynchronously
		go func() {
			fmt.Println("Starting FFmpeg chunking for:", savePath)
			if err := chunkVideo(savePath); err != nil {
				log.Printf("FFmpeg error for %s: %v\n", savePath, err)
			} else {
				log.Printf("Chunking completed for %s\n", savePath)
			}
		}()

		return c.JSON(fiber.Map{
			"message": "Video uploaded successfully",
			"path":    "/uploads/" + file.Filename,
		})
	})

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// List uploaded videos
	app.Get("/videos", func(c *fiber.Ctx) error {
		files, err := os.ReadDir("./uploads")
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Cannot read uploads folder")
		}

		var videos []map[string]string
		for _, f := range files {
			if !f.IsDir() {
				name := f.Name()
				// Only include mp4, mov, etc.
				if strings.HasSuffix(name, ".mp4") || strings.HasSuffix(name, ".mov") {
					videos = append(videos, map[string]string{
						"id":        name,
						"title":     name,
						"thumbnail": "https://picsum.photos/seed/" + name + "/640/360",
						"src":       "http://localhost:3001/uploads/" + name,
					})
				}
			}
		}

		return c.JSON(videos)
	})

	// Fallback route
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(404).SendString("Not Found")
	})

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nShutting down upload service...")
		_ = app.Shutdown()
	}()

	fmt.Printf("🚀 Upload service running at http://localhost:%s\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
