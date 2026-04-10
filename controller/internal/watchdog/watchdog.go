// Package watchdog implements systemd watchdog (sd_notify) integration.
// Sends READY=1 on startup, periodic WATCHDOG=1 heartbeats, and STOPPING=1 on shutdown.
// Heartbeat interval is auto-derived from WATCHDOG_USEC (recommended: send at half the timeout).
// If NOTIFY_SOCKET is not set (not running under systemd), all calls are no-ops.
package watchdog

import (
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// Ready sends READY=1 to systemd, signaling that the service has finished starting.
func Ready() {
	send("READY=1")
}

// Heartbeat sends WATCHDOG=1 to systemd.
func Heartbeat() {
	send("WATCHDOG=1")
}

// Stopping sends STOPPING=1 to systemd before shutdown.
func Stopping() {
	send("STOPPING=1")
}

// RecommendedInterval returns half of WATCHDOG_USEC from the environment.
// If WATCHDOG_USEC is not set or invalid, returns the provided fallback.
func RecommendedInterval(fallback time.Duration) time.Duration {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return fallback
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return fallback
	}
	// systemd recommends sending at half the timeout
	interval := time.Duration(usec/2) * time.Microsecond
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}

// RunHeartbeat sends WATCHDOG=1 at the recommended interval until done is closed.
func RunHeartbeat(done <-chan struct{}) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}

	interval := RecommendedInterval(10 * time.Second)
	log.Printf("watchdog: heartbeat every %v (NOTIFY_SOCKET=%s)", interval, sock)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			Heartbeat()
		}
	}
}

func send(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		log.Printf("watchdog: send %q failed: dial: %v", state, err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		log.Printf("watchdog: send %q failed: write: %v", state, err)
	}
}
