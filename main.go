package main

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

var serviceProcs []*os.Process

// Kill processes occupying a port
func killPort(port string) {
	switch runtime.GOOS {
	case "windows":
		psCmd := `
        $conn = Get-NetTCPConnection -LocalPort ` + port + ` -ErrorAction SilentlyContinue
        if ($conn) {
            $pid = $conn.OwningProcess
            if ($pid) { Stop-Process -Id $pid -Force; Write-Output "Killed process $pid on port ` + port + `" }
        }`
		cmd := exec.Command("powershell", "-Command", psCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error killing port %s: %v", port, err)
		}
		log.Printf("%s", strings.TrimSpace(string(out)))
	default: // Linux/macOS
		out, err := exec.Command("lsof", "-ti", "tcp:"+port).Output()
		if err != nil {
			log.Printf("No process found on port %s or lsof error: %v", port, err)
			return
		}
		for _, pid := range strings.Fields(string(out)) {
			exec.Command("kill", "-9", pid).Run()
			log.Printf("Killed process %s on port %s", pid, port)
		}
	}
}

// Start a microservice
func startService(name, dir string) {
	cmd := exec.Command("go", "run", "main.go")
	cmd.Dir = dir
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start %s: %v", name, err)
	}
	serviceProcs = append(serviceProcs, cmd.Process)
	log.Printf("%s started (PID %d)", name, cmd.Process.Pid)
}

func main() {
	// Kill ports that might conflict
	killPort("3000")
	killPort("3001")
	killPort("3002")
	killPort("8081") // gateway port

	// Microservices to start
	services := map[string]string{
		"auth-service":     "./auth-service",
		"upload-service":   "./upload-service",
		"social-service":   "./social-service",
		"playback-service": "./playback-service",
	}

	// Graceful shutdown of microservices
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("Shutting down services...")
		for _, proc := range serviceProcs {
			if proc != nil {
				proc.Kill()
				log.Printf("Killed service PID %d", proc.Pid)
			}
		}
		os.Exit(0)
	}()

	// Start all microservices
	for name, dir := range services {
		startService(name, dir)
	}

	// --------------------------
	// Start Gateway
	// --------------------------
	app := fiber.New()

	// CORS for frontend
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://127.0.0.1:8081, http://localhost:5173",
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// Serve React frontend from Vite build
	frontendDir := "./client/dist"
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

	// Proxy helper
	forward := func(prefix, target string) fiber.Handler {
		return func(c *fiber.Ctx) error {
			trimmed := strings.TrimPrefix(c.OriginalURL(), prefix)
			return proxy.Do(c, target+trimmed)
		}
	}

	// API proxy routes
	app.All("/auth/api/*", forward("/auth/api", "http://127.0.0.1:3000"))
	app.All("/upload/api/*", forward("/upload/api", "http://127.0.0.1:3001"))
	app.All("/social/api/*", forward("/social/api", "http://127.0.0.1:3002"))

	log.Println("Gateway running at http://127.0.0.1:8081")
	log.Fatal(app.Listen(":8081"))
}
