package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// --- Global variables to hold service URLs ---
var (
	esClient         = resty.New()
	searchServiceURL = ""
	socialServiceURL = ""
	publicURL        = ""
)

// Helper function to read Env Vars
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Printf("INFO: %s not set, defaulting to %s", key, fallback)
	return fallback
}

// ------------------- INDEX INTO ES ---------------------
// This function calls your Search Service API
func indexVideoInES(id, title, description, author string) {
	targetURL := fmt.Sprintf("%s/index", searchServiceURL)

	resp, err := esClient.R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]string{
			"id":          id,
			"title":       title,
			"description": description,
			"author":      author,
		}).
		Post(targetURL) // Use the environment variable URL

	if err != nil {
		log.Println("Error sending to Search Service:", err)
		return
	}
	if resp.IsError() {
		log.Println("Search Service error:", resp.String())
		return
	}
	log.Println("Indexed via Search Service:", resp.String())
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
		"-c:v", "h264", "-preset", "veryfast", "-profile:v", "baseline", "-level", "3.1",
		"-c:a", "aac", "-b:a", "128k",
		"-hls_time", "6",
		"-hls_playlist_type", "vod",
		"-hls_flags", "independent_segments",
		"-hls_segment_type", "mpegts",
		"-hls_list_size", "0",
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

	// --- Notify Socials service ---
	socialsTargetURL := fmt.Sprintf("%s/init", socialServiceURL)
	videoPublicURL := fmt.Sprintf("%s/uploads/%s", publicURL, file.Filename)

	resp, err := resty.New().R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{
			"id":          file.Filename,
			"title":       title,
			"description": description,
			"author":      uploader,
			"thumbnail":   "https://picsum.photos/seed/" + file.Filename + "/640/360",
			"path":        "http://98.70.25.253:3001/uploads/" + file.Filename, // Use the public URL
			"duration":    duration,
		}).Post(socialsTargetURL)

	if err != nil {
		log.Println("❌ Socials service failed:", err)
	} else if resp.IsError() {
		log.Println("❌ Socials service error:", resp.String())
	}

	// --- Index into Elasticsearch (via Search Service) ---
	go indexVideoInES(file.Filename, title, description, uploader)

	// --- Chunk video ---
	go func() {
		if err := chunkVideo(savePath); err != nil {
			log.Printf("FFmpeg error for %s: %v\n", savePath, err)
		}
	}()

	return c.JSON(fiber.Map{
		"message": "Video uploaded successfully",
		"path":    videoPublicURL,
	})
}

// ------------------- MAIN ------------------------------
func main() {
	// --- Read ALL service URLs from Environment Variables ---
	searchServiceURL = getEnv("SEARCH_SERVICE_URL", "http://localhost:8080")
	socialServiceURL = getEnv("SOCIAL_SERVICE_URL", "http://localhost:3002")
	publicURL = getEnv("PUBLIC_URL", "http://localhost:3001") // Self-referential for path construction
	// ---

	port := "3001"

	// Kill any process on the port
	fmt.Println("Cleaning any process using port", port)
	_ = exec.Command("fuser", "-k", port+"/tcp").Run() // Needs 'psmisc' package

	if err := waitForPortRelease(port, 3*time.Second); err != nil {
		log.Fatalf("Port %s is still busy: %v", port, err)
	}

	app := fiber.New(fiber.Config{
		BodyLimit: 1024 * 1024 * 1024, // 1 GB
	})

	// CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://98.70.25.253,http://98.70.25.253:5173,http://localhost:5173,http://98.70.25.253:3000,http://localhost:8081,http://98.70.25.253:8081",
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
		var socialData []struct {
			ID        string `json:"_id"`
			Title     string `json:"title"`
			Thumbnail string `json:"thumbnail"`
			Path      string `json:"path"`
			Author    string `json:"author"`
			Views     int    `json:"views"`
		}

		httpClient := resty.New()
		resp, err := httpClient.R().
			SetResult(&socialData).
			Get(fmt.Sprintf("%s/videos", socialServiceURL))

		if err != nil || resp.IsError() {
			log.Println("❌ Failed to fetch videos:", err, resp.String())
			return c.Status(500).JSON(fiber.Map{"error": "Failed to retrieve videos"})
		}

		var videos []map[string]string
		for _, v := range socialData {
			videos = append(videos, map[string]string{
				"id":        v.ID,
				"title":     v.Title,
				"thumbnail": v.Thumbnail,
				"src":       v.Path,
				"channel":   v.Author,
				"views":     fmt.Sprintf("%d", v.Views),
			})
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
