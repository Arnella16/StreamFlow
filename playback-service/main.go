package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	videoDir := "../upload-service/uploads/Screencast from 2025-09-13 01-00-32.webm_hls"

	// Serve HLS files with logging
	app.Get("/videos/*", func(c *fiber.Ctx) error {
		filePath := c.Params("*") // e.g. "segment1.ts" or "index.m3u8"
		fullPath := filepath.Join(videoDir, filePath)

		// Log to terminal
		if strings.HasSuffix(filePath, ".ts") || strings.HasSuffix(filePath, ".m3u8") || strings.HasSuffix(filePath, ".m4s") {
			log.Printf("📦 Requested: %s", filePath)
		}

		// Serve the file
		return c.SendFile(fullPath, true)
	})

	// Serve HTML player
	app.Get("/", func(c *fiber.Ctx) error {
		html := `
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>HLS Video Playback</title>
			<style>
				body {
					display: flex;
					flex-direction: column;
					align-items: center;
					justify-content: center;
					height: 100vh;
					background: #111;
					color: #eee;
					font-family: sans-serif;
				}
				video {
					width: 75%;
					border-radius: 12px;
					box-shadow: 0 0 15px rgba(255,255,255,0.2);
				}
			</style>
		</head>
		<body>
			<h1>HLS Playback</h1>
			<video id="video" controls autoplay></video>
			<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
			<script>
				const video = document.getElementById('video');
				const videoSrc = '/videos/index.m3u8';

				function logToServer(msg) {
					fetch('/log?msg=' + encodeURIComponent(msg))
				}

				if (Hls.isSupported()) {
					const hls = new Hls();
					hls.loadSource(videoSrc);
					hls.attachMedia(video);
					hls.on(Hls.Events.FRAG_LOADING, (event, data) => {
						const chunk = data.frag.relurl;
						console.log('🎬 Requesting chunk:', chunk);
						logToServer('Browser requested: ' + chunk);
					});
					hls.on(Hls.Events.MANIFEST_PARSED, () => video.play());
				} else if (video.canPlayType('application/vnd.apple.mpegurl')) {
					video.src = videoSrc;
					video.addEventListener('loadedmetadata', () => video.play());
				}
			</script>
		</body>
		</html>
		`
		c.Type("html")
		return c.SendString(html)
	})

	// Simple endpoint to receive logs from browser
	app.Get("/log", func(c *fiber.Ctx) error {
		msg := c.Query("msg", "")
		if msg != "" {
			log.Printf("🌐 Browser log: %s", msg)
		}
		return c.SendStatus(204)
	})

	port := 8080
	fmt.Printf("🚀 Server running at http://localhost:%d\n", port)
	log.Fatal(app.Listen(fmt.Sprintf(":%d", port)))
}
