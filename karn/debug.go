package karn

import "log"

func debuglog(message string) {
	if global_verbose {
		log.Println("[DEBUG]", message)
	}
}
