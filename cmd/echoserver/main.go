// cmd/echoserver — minimal MCP JSON-RPC echo server for red-team testing.
//
// Responds to every MCP method with a well-formed result and never blocks anything.
// Use as the upstream target when running SPIKEE, Promptfoo, or Garak against Aegir:
//
//	./bin/echo-server &           # start upstream on :8080
//	./bin/aegir                   # Aegir proxies to :8080
//	spikee test ... --target aegir_mcp_target
//
// Usage:
//
//	./bin/echo-server [-addr :8080] [-verbose]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type mcpRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      interface{} `json:"id"`
}

type mcpResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mcpResponse{
			JSONRPC: "2.0",
			Error: map[string]interface{}{
				"code":    -32700,
				"message": "parse error: " + err.Error(),
			},
			ID: nil,
		})
		return
	}

	var result interface{}
	switch req.Method {
	case "initialize":
		result = map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"serverInfo": map[string]interface{}{
				"name":    "aegir-echo-server",
				"version": "0.1.0",
			},
		}
	case "tools/list":
		result = map[string]interface{}{
			"tools": []map[string]interface{}{
				{
					"name":        "echo",
					"description": "Echoes input back as output — benign upstream test tool.",
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{"query": map[string]interface{}{"type": "string"}},
					},
				},
			},
		}
	case "tools/call":
		// Echo the arguments back in the content field so judges can read them.
		argsJSON, _ := json.Marshal(req.Params)
		result = map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("echo: %s", string(argsJSON)),
				},
			},
		}
	case "resources/list":
		result = map[string]interface{}{"resources": []interface{}{}}
	case "prompts/list":
		result = map[string]interface{}{"prompts": []interface{}{}}
	default:
		result = map[string]interface{}{"ok": true, "method": req.Method}
	}

	resp := mcpResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC(),
	})
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	verbose := flag.Bool("verbose", false, "log every request")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		handle(w, r)
	})

	log.Printf("aegir echo-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "echo-server: %v\n", err)
		os.Exit(1)
	}
}
