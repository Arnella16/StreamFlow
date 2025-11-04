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
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/go-resty/resty/v2"
)

var esClient = resty.New()

// ------------------- INDEX INTO ES ---------------------

func indexVideoInES(id, title, description, author string) {
	resp, err := esClient.R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]string{
			"id":          id,
			"title":       title,
			"description": description,
			"author":      author,
		}).
		Post("http://localhost:8080/index")

	if err != nil {
		log.Println("Error sending to Elasticsearch:", err)
		return
	}

	if resp.IsError() {
		log.Println("Elasticsearch error:", resp.String())
		return
	}

	log.Println("Indexed:", resp.String())
}

// ------------------- WAIT FOR PORT ---------------------

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

// ------------------- CHUNK VIDEO -----------------------

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

// ------------------- UPLOAD HANDLER ---------------------

func handleUpload(c *fiber.Ctx) error {
	file, err := c.FormFile("video")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "No video file uploaded")
	}

	// Extract metadata fields from form-data
    title := c.FormValue("title")
    description := c.FormValue("description")
    uploader := c.FormValue("uploader")
    durationStr := c.FormValue("duration")
	var duration float64
	if durationStr != "" {
		parsed, err := strconv.ParseFloat(durationStr, 64)
		if err == nil {
			duration = parsed
		}
	}

	uploadDir := "./uploads"
	savePath := filepath.Join(uploadDir, file.Filename)

	if err := c.SaveFile(file, savePath); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to save video")
	}

	// Notify Socials service
	resp, err := resty.New().R().
	SetHeader("Content-Type", "application/json").
	SetBody(map[string]interface{}{
		"id":          file.Filename,
		"title":       title,
		"description": description,
		"author":      uploader,
		"thumbnail":   "https://picsum.photos/seed/" + file.Filename + "/640/360",
		"path":        "http://localhost:3001/uploads/" + file.Filename,
		"duration":    duration, 
	}).Post("http://localhost:3002/init")


	if err != nil {
		log.Println("❌ Socials service failed:", err)
	} else if resp.IsError() {
		log.Println("❌ Socials service error:", resp.String())
	}

	// Index into Elasticsearch
	go indexVideoInES(file.Filename, file.Filename, "Uploaded video", "system")

	// Chunk video
	go func() {
		if err := chunkVideo(savePath); err != nil {
			log.Printf("FFmpeg error for %s: %v\n", savePath, err)
		}
	}()

	return c.JSON(fiber.Map{
		"message": "Video uploaded successfully",
		"path":    "/uploads/" + file.Filename,
	})
}

// ------------------- MAIN ------------------------------

func main() {
	port := "3001"

	// Kill any process on the port
	fmt.Println("Cleaning any process using port", port)
	_ = exec.Command("fuser", "-k", port+"/tcp").Run()

	if err := waitForPortRelease(port, 3*time.Second); err != nil {
		log.Fatalf("Port %s is still busy: %v", port, err)
	}

	app := fiber.New()

	// CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:8081,http://localhost:8081",
		AllowMethods:     "GET,POST,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// Create uploads folder
	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	// ---------------- ROUTES ----------------

	app.Static("/uploads", "./uploads")
	app.Static("/static", "./public")

	app.Post("/", handleUpload)
	app.Post("/upload", handleUpload)

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	app.Get("/videos", func(c *fiber.Ctx) error {
		files, err := os.ReadDir("./uploads")
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Cannot read uploads folder")
		}

		var videos []map[string]string

		for _, f := range files {
			if !f.IsDir() {
				name := f.Name()
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

	app.Use(func(c *fiber.Ctx) error {
		return c.Status(404).SendString("Not Found")
	})

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nShutting down upload service...")
		_ = app.Shutdown()
	}()

	fmt.Printf("🚀 Upload service running at http://localhost:%s\n", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}