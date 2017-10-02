package cli

import "log"

func debuglog(message string) {
	if globalVerbose {
		log.Println("[DEBUG]", message)
	}
}
