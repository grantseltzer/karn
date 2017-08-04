package karn

import "log"

func debuglog(message string) {
	if global_debug {
		log.Println("[DEBUG]", message)
	}
}
