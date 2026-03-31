package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stackscan/stackscan/internal/detect"
	"github.com/stackscan/stackscan/internal/output"
	"github.com/stackscan/stackscan/internal/scan"
)

var version = "dev"

func main() {
	jsonOut := flag.Bool("json", false, "output as JSON")
	compact := flag.Bool("compact", false, "compact one-line-per-category output")
	ver := flag.Bool("version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: stackscan [flags] [path]\n\n")
		fmt.Fprintf(os.Stderr, "Detect the tech stack of any project.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *ver {
		fmt.Printf("stackscan %s\n", version)
		return
	}

	target := "."
	if flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	abs, err := filepath.Abs(target)
	if err != nil {
		die("invalid path: %s", target)
	}

	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		die("not a directory: %s", abs)
	}

	start := time.Now()
	files, err := scan.Walk(abs)
	if err != nil {
		die("scan failed: %v", err)
	}

	matches := detect.Run(abs, files)
	elapsed := time.Since(start)

	switch {
	case *jsonOut:
		output.PrintJSON(matches)
	case *compact:
		output.PrintCompact(matches)
	default:
		fmt.Printf("\n  \033[1mstackscan\033[0m \033[2m%s\033[0m\n", filepath.Base(abs))
		fmt.Printf("  \033[2m%d files scanned in %dms\033[0m\n", len(files), elapsed.Milliseconds())
		output.PrintTable(matches)
	}
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
