package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/matusso/nyxr/internal/calibration"
)

func runCalibration(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "evaluate" {
		return errors.New("usage: nyxr calibration evaluate --dataset file")
	}
	fs := flag.NewFlagSet("calibration evaluate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("dataset", "", "labeled calibration dataset")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || len(fs.Args()) != 0 {
		return errors.New("usage: nyxr calibration evaluate --dataset file")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer f.Close()
	report, err := calibration.Evaluate(f)
	if err != nil {
		return fmt.Errorf("evaluate %s: %w", *path, err)
	}
	return json.NewEncoder(out).Encode(report)
}
