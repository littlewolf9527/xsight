package watchdog

import (
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

func Ready()    { send("READY=1") }
func Heartbeat() { send("WATCHDOG=1") }
func Stopping()  { send("STOPPING=1") }

func RecommendedInterval(fallback time.Duration) time.Duration {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return fallback
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return fallback
	}
	interval := time.Duration(usec/2) * time.Microsecond
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}

func RunHeartbeat(done <-chan struct{}) {
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return
	}
	interval := RecommendedInterval(10 * time.Second)
	log.Printf("watchdog: heartbeat every %v", interval)
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
