package main

import (
	"log"
	"os"
	"os/exec"
)

func main() {

	entitlements := []string{
		"default", // Allow Default syscalls
		// "exec",    // Allow exec
	}

	err := ApplyEntitlements(entitlements)
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("echo", "I JUST EXEC'D!")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}
