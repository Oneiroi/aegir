package telemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds OpenTelemetry configuration.
type Config struct {
	Enabled     bool   `json:"enabled" mapstructure:"enabled"`
	OutputDir   string `json:"output_dir" mapstructure:"output_dir"`
	ServiceName string `json:"service_name" mapstructure:"service_name"`
	SampleRate  float64 `json:"sample_rate" mapstructure:"sample_rate"`
}

// Provider wraps the OTEL TracerProvider and the underlying trace file.
type Provider struct {
	tp   *sdktrace.TracerProvider
	file *os.File
}

// Tracer returns a named tracer from the global provider.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// New initialises an OTEL TracerProvider that writes JSON spans to a file under
// cfg.OutputDir. The file is named traces-<date>.jsonl and is appended on each run.
// Returns a no-op provider when OTEL is disabled.
func New(cfg Config) (*Provider, error) {
	if !cfg.Enabled {
		// Install a no-op provider so callers don't need to nil-check.
		tp := sdktrace.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return &Provider{tp: tp}, nil
	}

	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("otel: create output dir: %w", err)
	}

	traceFile := filepath.Join(cfg.OutputDir, fmt.Sprintf("traces-%s.jsonl", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(traceFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("otel: open trace file %s: %w", traceFile, err)
	}

	exporter, err := stdouttrace.New(
		stdouttrace.WithWriter(f),
	)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("otel: create exporter: %w", err)
	}

	sampleRate := cfg.SampleRate
	if sampleRate <= 0 || sampleRate > 1 {
		sampleRate = 1.0
	}

	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
		),
	)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("otel: create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
	)

	otel.SetTracerProvider(tp)

	return &Provider{tp: tp, file: f}, nil
}

// Shutdown flushes and closes the provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if err := p.tp.Shutdown(ctx); err != nil {
		return err
	}
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}
