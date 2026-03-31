package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/stackscan/stackscan/internal/detect"
)

func PrintTable(matches []detect.Match) {
	if len(matches) == 0 {
		fmt.Println("  No technologies detected.")
		return
	}

	grouped := groupByCategory(matches)
	order := []detect.Category{
		detect.Language, detect.Framework, detect.Database, detect.PkgMgr,
		detect.Bundler, detect.Styling, detect.Testing, detect.Linting,
		detect.CI, detect.Infra, detect.Runtime,
	}

	for _, cat := range order {
		items, ok := grouped[cat]
		if !ok {
			continue
		}

		sort.Slice(items, func(i, j int) bool {
			return items[i].Confidence > items[j].Confidence
		})

		fmt.Printf("\n  \033[1m%s\033[0m\n", categoryLabel(cat))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, m := range items {
			bar := confidenceBar(m.Confidence)
			evidence := ""
			if len(m.Evidence) > 0 {
				evidence = "\033[2m" + strings.Join(m.Evidence, ", ") + "\033[0m"
			}
			fmt.Fprintf(w, "    %s  %s\t%s\n", bar, m.Name, evidence)
		}
		w.Flush()
	}

	fmt.Println()
}

func PrintJSON(matches []detect.Match) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(matches)
}

func PrintCompact(matches []detect.Match) {
	grouped := groupByCategory(matches)
	for cat, items := range grouped {
		names := make([]string, len(items))
		for i, m := range items {
			names[i] = m.Name
		}
		fmt.Printf("%s: %s\n", categoryLabel(cat), strings.Join(names, ", "))
	}
}

func groupByCategory(matches []detect.Match) map[detect.Category][]detect.Match {
	grouped := map[detect.Category][]detect.Match{}
	for _, m := range matches {
		grouped[m.Category] = append(grouped[m.Category], m)
	}
	return grouped
}

func categoryLabel(c detect.Category) string {
	labels := map[detect.Category]string{
		detect.Language:  "Languages",
		detect.Framework: "Frameworks & Libraries",
		detect.Database:  "Databases & Storage",
		detect.PkgMgr:   "Package Managers",
		detect.Bundler:   "Build Tools",
		detect.Styling:   "Styling",
		detect.Testing:   "Testing",
		detect.Linting:   "Linting & Formatting",
		detect.CI:        "CI/CD & Deployment",
		detect.Infra:     "Infrastructure",
		detect.Runtime:   "Runtime",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return string(c)
}

func confidenceBar(c float64) string {
	if c >= 0.9 {
		return "\033[32m●\033[0m"
	}
	if c >= 0.7 {
		return "\033[33m●\033[0m"
	}
	return "\033[2m●\033[0m"
}
