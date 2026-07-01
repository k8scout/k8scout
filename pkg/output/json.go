package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hac01/k8scout/pkg/graph"
	"go.uber.org/zap"
)

// Writer handles both stdout printing and file writing.
type Writer struct {
	format string
	log    *zap.Logger
}

// New creates a new output Writer.
func New(format string, log *zap.Logger) *Writer {
	return &Writer{format: format, log: log}
}

// WriteFile serializes the report to a JSON file.
func (w *Writer) WriteFile(report Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// Print writes the report to stdout (JSON or text based on format flag).
func (w *Writer) Print(report Report) error {
	switch w.format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(report)
	case "sarif":
		sarif := ConvertToSARIF(report.RiskFindings, report.Meta)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(sarif)
	default:
		return printText(report)
	}
}

// WriteSARIFFile serializes findings to a SARIF v2.1.0 JSON file.
func (w *Writer) WriteSARIFFile(findings []graph.RiskFinding, meta MetaBlock, path string) error {
	sarif := ConvertToSARIF(findings, meta)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating SARIF file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sarif)
}

// WriteReviewerFile serializes the reviewer report to a JSON file.
func (w *Writer) WriteReviewerFile(report ReviewerReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// PrintReviewer writes the reviewer report to stdout (JSON or text based on format flag).
func (w *Writer) PrintReviewer(report ReviewerReport) error {
	if w.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(report)
	}
	return printReviewerText(report)
}
