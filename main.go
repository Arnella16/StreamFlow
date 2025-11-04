package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

var serviceProcs []*os.Process

// Start NPM/Vite dev server
func startNpmDev(dir string) {
    cmd := exec.Command("npm", "run", "dev")
    cmd.Dir = dir
    cmd.Stdout = log.Writer()
    cmd.Stderr = log.Writer()

    if err := cmd.Start(); err != nil {
        log.Fatalf("Failed to start Vite dev server: %v", err)
    }

    serviceProcs = append(serviceProcs, cmd.Process)
    log.Printf("Vite dev server started (PID %d)", cmd.Process.Pid)
}


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
			_ = exec.Command("kill", "-9", pid).Run()
			log.Printf("Killed process %s on port %s", pid, port)
		}
	}
}

// waitForTCP polls an address until it accepts TCP connections or times out
func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

// Start a microservice
func startService(name, dir, addr string) {
	cmd := exec.Command("go", "run", "main.go")
	cmd.Dir = dir
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start %s: %v", name, err)
	}
	serviceProcs = append(serviceProcs, cmd.Process)
	log.Printf("%s started (PID %d)", name, cmd.Process.Pid)

	// wait for service to accept TCP connections (non-fatal)
	if addr != "" {
		if err := waitForTCP(addr, 10*time.Second); err != nil {
			log.Printf("Warning: %s may not be ready at %s: %v", name, addr, err)
		} else {
			log.Printf("✅ %s is listening at %s", name, addr)
		}
	}
}

func main() {
	// Kill ports that might conflict
	killPort("3000") // auth
	killPort("3001") // upload
	killPort("3002") // social
	killPort("8080") // search/playback (Elasticsearch)
	killPort("8083") // HLS streaming
	killPort("8081") // gateway
	killPort("5173") // Vite dev server


	// Microservices to start
	services := []struct {
		name string
		dir  string
		addr string
	}{
		{"auth-service", "./auth-service", "127.0.0.1:3000"},
		{"upload-service", "./upload-service", "127.0.0.1:3001"},
		{"social-service", "./social-service", "127.0.0.1:3002"},
		{"search-service", "./search-service", "127.0.0.1:8080"},
		{"hls-service", "./playback-service", "127.0.0.1:8083"},
	}

	// Graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("\n🛑 Shutting down services...")
		for _, proc := range serviceProcs {
			if proc != nil {
				_ = proc.Kill()
				log.Printf("Killed service PID %d", proc.Pid)
			}
		}
		os.Exit(0)
	}()

	// Start all microservices
	for _, s := range services {
		startService(s.name, s.dir, s.addr)
	}

	// Run Vite frontend in dev mode
	startNpmDev("./client")


	// --------------------------
	// Start Gateway
	// --------------------------
	app := fiber.New()

	// CORS for frontend
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://127.0.0.1:8081,http://localhost:5173",
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// Serve React frontend from Vite build
	frontendDir := "./client/dist"
	app.Static("/", frontendDir)

	// Fallback for React Router - allow API and HLS routes through
	app.Use(func(c *fiber.Ctx) error {
		path := c.Path()
		if strings.HasPrefix(path, "/auth/api") ||
			strings.HasPrefix(path, "/upload/api") ||
			strings.HasPrefix(path, "/social/api") ||
			strings.HasPrefix(path, "/search/api") ||
			strings.HasPrefix(path, "/hls") {
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
	app.All("/search/api/*", forward("/search/api", "http://127.0.0.1:8080"))
	app.All("/hls/*", forward("/hls", "http://127.0.0.1:8083"))

	log.Println("🚀 Gateway running at http://127.0.0.1:8081")
	log.Fatal(app.Listen(":8081"))
}
