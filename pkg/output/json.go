package output

import (
	"encoding/json"
	"fmt"
	"os"

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
	if w.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(report)
	}
	// Default to text summary.
	return printText(report)
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
