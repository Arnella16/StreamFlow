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
)

var serviceProcs []*os.Process

// killPort attempts to free a given TCP port across platforms
func killPort(port string) {
	switch runtime.GOOS {
	case "windows":
		// PowerShell script to kill a process only if it exists
		psCmd := `
        $conn = Get-NetTCPConnection -LocalPort ` + port + ` -ErrorAction SilentlyContinue
        if ($conn) {
            $pid = $conn.OwningProcess
            if ($pid) {
                Stop-Process -Id $pid -Force
                Write-Output "Killed process $pid on port ` + port + `"
            } else {
                Write-Output "No PID found for port ` + port + `"
            }
        } else {
            Write-Output "No process found on port ` + port + `"
        }`
		cmd := exec.Command("powershell", "-Command", psCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error checking/killing port %s: %v", port, err)
		}
		log.Printf("%s", strings.TrimSpace(string(out)))

	default: // Linux/macOS
		out, err := exec.Command("lsof", "-ti", "tcp:"+port).Output()
		if err != nil {
			log.Printf("No process found on port %s or lsof error: %v", port, err)
			return
		}
		pids := strings.Fields(string(out))
		for _, pid := range pids {
			exec.Command("kill", "-9", pid).Run()
			log.Printf("Killed process %s on port %s", pid, port)
		}
	}
}

// startService runs a Go service in a specified directory
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
	// Kill processes on ports that might cause trouble
	killPort("3000") // Kill anything on port 3000
	killPort("3001") // Kill anything on port 3001 if needed

	services := map[string]string{
		"auth-service":   "./auth-service",
		"upload-service": "./upload-service",
		// Add more services here if needed
	}

	// Handle termination signals to clean up child processes
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("Received termination signal, shutting down services...")
		for _, proc := range serviceProcs {
			if proc != nil {
				proc.Kill()
				log.Printf("Killed service process PID %d", proc.Pid)
			}
		}
		os.Exit(0)
	}()

	// Start each service
	for name, dir := range services {
		startService(name, dir)
	}

	// Main Fiber app (just a simple control endpoint)
	app := fiber.New()

	// Enable CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://127.0.0.1:3000", // Allowed origins
		AllowMethods:     "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Welcome to StreamFlow!")
	})

	// Start a small HTTP server on a management port (optional)
	go func() {
		if err := app.Listen(":4000"); err != nil {
			log.Fatalf("Failed to start management server: %v", err)
		}
	}()

	// Prevent main from exiting
	select {}
}
