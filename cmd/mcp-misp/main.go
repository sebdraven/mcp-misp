// Command mcp-misp serves a MISP instance over MCP.
//
// Every answer comes from a live instance run by someone else: nothing is
// cached beyond a few descriptions of the instance itself, no taxonomy or
// tagging convention is assumed, and the tool set is deliberately small. The
// design constraint throughout is volume — a MISP event can carry tens of
// thousands of attributes, so results are projected, capped and paginated
// rather than dumped.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/mcptools"
	"github.com/sebdraven/mcp-misp/internal/misp"
	"github.com/sebdraven/mcp-misp/internal/service"
)

// Stamped at build time. The defaults are deliberately not numbers: a locally
// built binary that announces a release version lies to whoever reads it, and
// the MCP client shows this string as the server's identity.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	transport := flag.String("transport", "", "transport: stdio or http (overrides MCP_TRANSPORT)")
	addr := flag.String("addr", "", "HTTP listen address (overrides MCP_HTTP_ADDR)")
	showVer := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVer {
		// Bare version on the first line, matching the sibling MCP servers, so
		// `head -1` stays a usable version string.
		fmt.Println(version)
		fmt.Printf("commit %s\n", commit)
		fmt.Printf("built  %s\n", buildDate)
		return
	}

	// Flags win over the environment, so they are applied before Load validates
	// the pair — in particular the loopback guard on the listen address.
	if *transport != "" {
		os.Setenv("MCP_TRANSPORT", *transport)
	}
	if *addr != "" {
		os.Setenv("MCP_HTTP_ADDR", *addr)
	}

	// stdio speaks JSON-RPC on stdout, so every log line goes to stderr or it
	// corrupts the protocol stream.
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	for _, w := range cfg.Warnings {
		log.Printf("warning: %s", w)
	}

	client := misp.New(cfg.URL, cfg.Key(),
		misp.WithTimeout(cfg.Timeout),
		misp.WithInsecureSkipVerify(!cfg.VerifySSL),
		misp.WithMaxConcurrency(cfg.MaxConcurrency),
		misp.WithRetries(cfg.MaxRetries),
	)

	svc := service.New(client, cfg)
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-misp", Version: version}, nil)
	tools := mcptools.RegisterAll(server, svc)

	mode := "read-only"
	if !cfg.ReadOnly {
		mode = "read-write"
	}
	log.Printf("%d tools registered (%s)", len(tools), mode)

	switch cfg.Transport {
	case "stdio":
		log.Printf("mcp-misp %s on stdio, %s, instance %s", version, mode, cfg.URL)
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
	case "http":
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("mcp-misp %s on %s (streamable HTTP), %s, instance %s", version, cfg.HTTPAddr, mode, cfg.URL)
		// A header timeout, so a client that opens a connection and never
		// finishes its request cannot hold a slot indefinitely. No write or
		// read timeout: streamable HTTP keeps responses open by design.
		srv := &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}
