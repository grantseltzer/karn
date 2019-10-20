package entitlements

import (
	"log"
	"os"
)

func logIfEnabled(format string, v ...interface{}) {
	if os.Getenv("KARN_LOG") != "" {
		log.Printf("[karn] "+format, v...)
	}
}
