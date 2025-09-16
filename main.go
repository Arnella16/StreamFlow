package main

import (
	"log"
	"os/exec"
)

func startService(name, dir string) {
	cmd := exec.Command("go", "run", "main.go")
	cmd.Dir = dir
	cmd.Stdout = log.Writer()
	cmd.Stderr = log.Writer()
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start %s: %v", name, err)
	}
	log.Printf("%s started (PID %d)", name, cmd.Process.Pid)
}

func main() {
	services := map[string]string{
		"auth-service":  "./auth-service",
		"video-service": "./video-service",
		// "social-service":   "./social-service",
		// "search-service":   "./search-service",
		// "playback-service": "./playback-service",
	}

	for name, dir := range services {
		startService(name, dir)
	}

	// Prevent main from exiting
	select {}
}
