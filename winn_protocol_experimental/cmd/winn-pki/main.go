package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/pki"
)

func main() {
	var outputDir string
	var serverName string
	var deviceID string
	flag.StringVar(&outputDir, "out", "", "new empty directory for lab PKI files")
	flag.StringVar(&serverName, "server-name", "localhost", "controller DNS name or IP")
	flag.StringVar(&deviceID, "device-id", "android-lab-1", "device identity for the client certificate")
	flag.Parse()
	if outputDir == "" {
		exitError("-out is required")
	}
	paths, err := pki.GenerateLab(outputDir, serverName, deviceID, time.Now().UTC())
	if err != nil {
		exitError(err.Error())
	}
	encoded, err := json.MarshalIndent(paths, "", "  ")
	if err != nil {
		exitError(err.Error())
	}
	fmt.Println(string(encoded))
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-pki:", message)
	os.Exit(1)
}
