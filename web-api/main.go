package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

type ScanRequest struct {
	IP       string `json:"ip"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Protocol string `json:"protocol"`
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("../netscout", req.IP, fmt.Sprint(req.Start), fmt.Sprint(req.End), "1", req.Protocol)
	
	err := cmd.Run()
    if err != nil {
        fmt.Println("Command execution failed:", err) 
        http.Error(w, "Scan failed", http.StatusInternalServerError)
        return
    }

	http.ServeFile(w, r, "../report.json")
}

func main() {
    http.Handle("/", http.FileServer(http.Dir("./static")))
    
    http.HandleFunc("/scan", scanHandler)
    fmt.Println("Server started at http://localhost:8080")
    http.ListenAndServe(":8080", nil)
}
