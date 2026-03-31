package detect

import (
	"strings"

	"github.com/stackscan/stackscan/internal/scan"
)

func Run(root string, files []scan.FileInfo) []Match {
	var matches []Match

	matches = append(matches, detectLanguages(files)...)
	matches = append(matches, detectPackageManagers(files)...)
	matches = append(matches, detectFrameworks(root, files)...)
	matches = append(matches, detectDatabases(root, files)...)
	matches = append(matches, detectTesting(root, files)...)
	matches = append(matches, detectLinting(files)...)
	matches = append(matches, detectCI(files)...)
	matches = append(matches, detectBundlers(files)...)
	matches = append(matches, detectInfra(files)...)
	matches = append(matches, detectStyling(root, files)...)
	matches = append(matches, detectRuntime(files)...)

	return dedupe(matches)
}

func dedupe(matches []Match) []Match {
	seen := map[string]bool{}
	var out []Match
	for _, m := range matches {
		key := string(m.Category) + ":" + m.Name
		if !seen[key] {
			seen[key] = true
			out = append(out, m)
		}
	}
	return out
}

func detectLanguages(files []scan.FileInfo) []Match {
	type langDef struct {
		exts []string
		name string
	}

	langs := []langDef{
		{[]string{"go"}, "Go"},
		{[]string{"rs"}, "Rust"},
		{[]string{"ts", "tsx"}, "TypeScript"},
		{[]string{"js", "jsx", "mjs", "cjs"}, "JavaScript"},
		{[]string{"py", "pyw"}, "Python"},
		{[]string{"rb"}, "Ruby"},
		{[]string{"java"}, "Java"},
		{[]string{"kt", "kts"}, "Kotlin"},
		{[]string{"swift"}, "Swift"},
		{[]string{"cs"}, "C#"},
		{[]string{"cpp", "cc", "cxx"}, "C++"},
		{[]string{"c", "h"}, "C"},
		{[]string{"php"}, "PHP"},
		{[]string{"dart"}, "Dart"},
		{[]string{"ex", "exs"}, "Elixir"},
		{[]string{"zig"}, "Zig"},
		{[]string{"lua"}, "Lua"},
		{[]string{"scala"}, "Scala"},
		{[]string{"r", "R"}, "R"},
		{[]string{"sql"}, "SQL"},
		{[]string{"sh", "bash", "zsh"}, "Shell"},
	}

	var matches []Match
	for _, l := range langs {
		total := 0
		for _, ext := range l.exts {
			total += scan.CountExt(files, ext)
		}
		if total > 0 {
			conf := 0.5
			if total > 5 {
				conf = 0.8
			}
			if total > 20 {
				conf = 1.0
			}
			matches = append(matches, Match{
				Name:       l.name,
				Category:   Language,
				Confidence: conf,
				Evidence:   []string{strings.Join(l.exts, ", ") + " files found"},
			})
		}
	}

	return matches
}

func detectPackageManagers(files []scan.FileInfo) []Match {
	checks := []struct {
		file string
		name string
	}{
		{"package.json", "npm"},
		{"yarn.lock", "Yarn"},
		{"pnpm-lock.yaml", "pnpm"},
		{"bun.lockb", "Bun"},
		{"go.mod", "Go Modules"},
		{"Cargo.toml", "Cargo"},
		{"requirements.txt", "pip"},
		{"Pipfile", "Pipenv"},
		{"pyproject.toml", "Poetry/PDM"},
		{"Gemfile", "Bundler"},
		{"composer.json", "Composer"},
		{"build.gradle", "Gradle"},
		{"pom.xml", "Maven"},
		{"Package.swift", "Swift PM"},
		{"pubspec.yaml", "Pub (Dart)"},
		{"mix.exs", "Mix (Elixir)"},
	}

	var matches []Match
	for _, c := range checks {
		if scan.HasFile(files, c.file) {
			matches = append(matches, Match{
				Name:       c.name,
				Category:   PkgMgr,
				Confidence: 1.0,
				Evidence:   []string{c.file},
			})
		}
	}
	return matches
}

func detectFrameworks(root string, files []scan.FileInfo) []Match {
	var matches []Match

	// check package.json deps
	if scan.HasFile(files, "package.json") {
		pkg, err := scan.ReadFileHead(root, "package.json", 8192)
		if err == nil {
			depChecks := []struct {
				dep  string
				name string
			}{
				{"next", "Next.js"},
				{"nuxt", "Nuxt"},
				{"react", "React"},
				{"vue", "Vue"},
				{"svelte", "Svelte"},
				{"@sveltejs/kit", "SvelteKit"},
				{"angular", "Angular"},
				{"express", "Express"},
				{"fastify", "Fastify"},
				{"hono", "Hono"},
				{"@nestjs/core", "NestJS"},
				{"astro", "Astro"},
				{"remix", "Remix"},
				{"solid-js", "SolidJS"},
				{"gatsby", "Gatsby"},
				{"electron", "Electron"},
				{"react-native", "React Native"},
				{"expo", "Expo"},
				{"three", "Three.js"},
				{"@tanstack/react-query", "TanStack Query"},
				{"prisma", "Prisma"},
				{"drizzle-orm", "Drizzle ORM"},
				{"mongoose", "Mongoose"},
				{"sequelize", "Sequelize"},
				{"trpc", "tRPC"},
				{"@trpc/server", "tRPC"},
				{"socket.io", "Socket.IO"},
			}

			for _, d := range depChecks {
				if strings.Contains(pkg, `"`+d.dep+`"`) {
					matches = append(matches, Match{
						Name:       d.name,
						Category:   Framework,
						Confidence: 0.95,
						Evidence:   []string{"package.json dependency"},
					})
				}
			}
		}
	}

	// python frameworks
	if scan.HasFile(files, "requirements.txt") || scan.HasFile(files, "pyproject.toml") {
		for _, fname := range []string{"requirements.txt", "pyproject.toml", "Pipfile"} {
			content, err := scan.ReadFileHead(root, fname, 4096)
			if err != nil {
				continue
			}
			pyChecks := []struct {
				pkg  string
				name string
			}{
				{"django", "Django"},
				{"flask", "Flask"},
				{"fastapi", "FastAPI"},
				{"starlette", "Starlette"},
				{"tornado", "Tornado"},
				{"celery", "Celery"},
				{"sqlalchemy", "SQLAlchemy"},
				{"pydantic", "Pydantic"},
			}
			lower := strings.ToLower(content)
			for _, c := range pyChecks {
				if strings.Contains(lower, c.pkg) {
					matches = append(matches, Match{
						Name:       c.name,
						Category:   Framework,
						Confidence: 0.9,
						Evidence:   []string{fname},
					})
				}
			}
		}
	}

	// go frameworks
	if scan.HasFile(files, "go.mod") {
		gomod, err := scan.ReadFileHead(root, "go.mod", 4096)
		if err == nil {
			goChecks := []struct {
				mod  string
				name string
			}{
				{"gin-gonic/gin", "Gin"},
				{"gofiber/fiber", "Fiber"},
				{"labstack/echo", "Echo"},
				{"gorilla/mux", "Gorilla Mux"},
				{"go-chi/chi", "Chi"},
				{"charmbracelet/bubbletea", "Bubble Tea"},
				{"cobra", "Cobra"},
				{"urfave/cli", "urfave/cli"},
				{"gorm.io/gorm", "GORM"},
			}
			for _, c := range goChecks {
				if strings.Contains(gomod, c.mod) {
					matches = append(matches, Match{
						Name:       c.name,
						Category:   Framework,
						Confidence: 0.95,
						Evidence:   []string{"go.mod"},
					})
				}
			}
		}
	}

	// rust frameworks
	if scan.HasFile(files, "Cargo.toml") {
		cargo, err := scan.ReadFileHead(root, "Cargo.toml", 4096)
		if err == nil {
			rustChecks := []struct {
				crate string
				name  string
			}{
				{"actix-web", "Actix Web"},
				{"axum", "Axum"},
				{"rocket", "Rocket"},
				{"tokio", "Tokio"},
				{"serde", "Serde"},
				{"clap", "Clap"},
				{"tauri", "Tauri"},
			}
			for _, c := range rustChecks {
				if strings.Contains(cargo, c.crate) {
					matches = append(matches, Match{
						Name:       c.name,
						Category:   Framework,
						Confidence: 0.95,
						Evidence:   []string{"Cargo.toml"},
					})
				}
			}
		}
	}

	// flutter
	if scan.HasFile(files, "pubspec.yaml") {
		pub, _ := scan.ReadFileHead(root, "pubspec.yaml", 2048)
		if strings.Contains(pub, "flutter") {
			matches = append(matches, Match{Name: "Flutter", Category: Framework, Confidence: 1.0, Evidence: []string{"pubspec.yaml"}})
		}
	}

	// ruby
	if scan.HasFile(files, "Gemfile") {
		gem, _ := scan.ReadFileHead(root, "Gemfile", 4096)
		if strings.Contains(gem, "rails") {
			matches = append(matches, Match{Name: "Ruby on Rails", Category: Framework, Confidence: 1.0, Evidence: []string{"Gemfile"}})
		}
		if strings.Contains(gem, "sinatra") {
			matches = append(matches, Match{Name: "Sinatra", Category: Framework, Confidence: 0.95, Evidence: []string{"Gemfile"}})
		}
	}

	return matches
}

func detectDatabases(root string, files []scan.FileInfo) []Match {
	var matches []Match

	// docker-compose is a goldmine
	for _, f := range files {
		if f.Name == "docker-compose.yml" || f.Name == "docker-compose.yaml" || f.Name == "compose.yml" {
			content, err := scan.ReadFileHead(root, f.Path, 4096)
			if err != nil {
				continue
			}
			dbChecks := []struct {
				image string
				name  string
			}{
				{"postgres", "PostgreSQL"},
				{"mysql", "MySQL"},
				{"mariadb", "MariaDB"},
				{"mongo", "MongoDB"},
				{"redis", "Redis"},
				{"elasticsearch", "Elasticsearch"},
				{"meilisearch", "Meilisearch"},
				{"minio", "MinIO"},
				{"rabbitmq", "RabbitMQ"},
				{"nats", "NATS"},
				{"clickhouse", "ClickHouse"},
			}
			lower := strings.ToLower(content)
			for _, c := range dbChecks {
				if strings.Contains(lower, c.image) {
					matches = append(matches, Match{
						Name:       c.name,
						Category:   Database,
						Confidence: 0.9,
						Evidence:   []string{f.Name},
					})
				}
			}
		}
	}

	// prisma schema
	if scan.HasFileAnywhere(files, "schema.prisma") {
		matches = append(matches, Match{Name: "Prisma", Category: Database, Confidence: 1.0, Evidence: []string{"schema.prisma"}})
	}

	// .env files often contain DB URLs
	if scan.HasFile(files, ".env.example") || scan.HasFile(files, ".env.local") {
		for _, name := range []string{".env.example", ".env.local"} {
			content, err := scan.ReadFileHead(root, name, 2048)
			if err != nil {
				continue
			}
			upper := strings.ToUpper(content)
			if strings.Contains(upper, "POSTGRES") || strings.Contains(upper, "DATABASE_URL") {
				matches = append(matches, Match{Name: "PostgreSQL", Category: Database, Confidence: 0.6, Evidence: []string{name}})
			}
			if strings.Contains(upper, "MONGODB") || strings.Contains(upper, "MONGO_URI") {
				matches = append(matches, Match{Name: "MongoDB", Category: Database, Confidence: 0.6, Evidence: []string{name}})
			}
			if strings.Contains(upper, "REDIS") {
				matches = append(matches, Match{Name: "Redis", Category: Database, Confidence: 0.6, Evidence: []string{name}})
			}
		}
	}

	// sqlite
	if scan.HasExt(files, "db") || scan.HasExt(files, "sqlite") || scan.HasExt(files, "sqlite3") {
		matches = append(matches, Match{Name: "SQLite", Category: Database, Confidence: 0.8, Evidence: []string{"database file"}})
	}

	// supabase
	if scan.HasFile(files, "supabase") || scan.HasFileAnywhere(files, "supabase.ts") {
		matches = append(matches, Match{Name: "Supabase", Category: Database, Confidence: 0.8, Evidence: []string{"supabase config"}})
	}

	// firebase
	if scan.HasFile(files, "firebase.json") || scan.HasFile(files, ".firebaserc") {
		matches = append(matches, Match{Name: "Firebase", Category: Database, Confidence: 0.9, Evidence: []string{"firebase config"}})
	}

	return matches
}

func detectTesting(root string, files []scan.FileInfo) []Match {
	var matches []Match

	fileChecks := []struct {
		file string
		name string
	}{
		{"jest.config.js", "Jest"},
		{"jest.config.ts", "Jest"},
		{"vitest.config.ts", "Vitest"},
		{"vitest.config.js", "Vitest"},
		{"cypress.config.ts", "Cypress"},
		{"cypress.config.js", "Cypress"},
		{"playwright.config.ts", "Playwright"},
		{"playwright.config.js", "Playwright"},
		{".mocharc.yml", "Mocha"},
		{"pytest.ini", "pytest"},
		{"conftest.py", "pytest"},
		{"phpunit.xml", "PHPUnit"},
	}

	for _, c := range fileChecks {
		if scan.HasFile(files, c.file) || scan.HasFileAnywhere(files, c.file) {
			matches = append(matches, Match{Name: c.name, Category: Testing, Confidence: 1.0, Evidence: []string{c.file}})
		}
	}

	// check package.json for test deps
	if scan.HasFile(files, "package.json") {
		pkg, _ := scan.ReadFileHead(root, "package.json", 8192)
		testDeps := []struct {
			dep  string
			name string
		}{
			{"jest", "Jest"},
			{"vitest", "Vitest"},
			{"mocha", "Mocha"},
			{"cypress", "Cypress"},
			{"playwright", "Playwright"},
			{"@testing-library", "Testing Library"},
			{"ava", "AVA"},
			{"tap", "TAP"},
		}
		for _, d := range testDeps {
			if strings.Contains(pkg, `"`+d.dep+`"`) {
				matches = append(matches, Match{Name: d.name, Category: Testing, Confidence: 0.9, Evidence: []string{"package.json"}})
			}
		}
	}

	// go test files
	for _, f := range files {
		if strings.HasSuffix(f.Name, "_test.go") {
			matches = append(matches, Match{Name: "Go testing", Category: Testing, Confidence: 1.0, Evidence: []string{"*_test.go files"}})
			break
		}
	}

	return matches
}

func detectLinting(files []scan.FileInfo) []Match {
	var matches []Match

	checks := []struct {
		file string
		name string
	}{
		{".eslintrc.js", "ESLint"},
		{".eslintrc.json", "ESLint"},
		{".eslintrc.cjs", "ESLint"},
		{"eslint.config.js", "ESLint"},
		{"eslint.config.mjs", "ESLint"},
		{".prettierrc", "Prettier"},
		{".prettierrc.json", "Prettier"},
		{"prettier.config.js", "Prettier"},
		{"biome.json", "Biome"},
		{".golangci.yml", "golangci-lint"},
		{"rustfmt.toml", "rustfmt"},
		{"clippy.toml", "Clippy"},
		{".rubocop.yml", "RuboCop"},
		{".flake8", "Flake8"},
		{"mypy.ini", "mypy"},
		{".editorconfig", "EditorConfig"},
		{"stylelint.config.js", "Stylelint"},
		{".stylelintrc", "Stylelint"},
	}

	for _, c := range checks {
		if scan.HasFile(files, c.file) {
			matches = append(matches, Match{Name: c.name, Category: Linting, Confidence: 1.0, Evidence: []string{c.file}})
		}
	}

	return matches
}

func detectCI(files []scan.FileInfo) []Match {
	var matches []Match

	for _, f := range files {
		switch {
		case strings.HasPrefix(f.Path, ".github/workflows/"):
			matches = append(matches, Match{Name: "GitHub Actions", Category: CI, Confidence: 1.0, Evidence: []string{f.Path}})
			return matches
		}
	}

	ciChecks := []struct {
		file string
		name string
	}{
		{".gitlab-ci.yml", "GitLab CI"},
		{"Jenkinsfile", "Jenkins"},
		{".circleci/config.yml", "CircleCI"},
		{".travis.yml", "Travis CI"},
		{"bitbucket-pipelines.yml", "Bitbucket Pipelines"},
		{".drone.yml", "Drone CI"},
		{"railway.json", "Railway"},
		{"vercel.json", "Vercel"},
		{"netlify.toml", "Netlify"},
		{"render.yaml", "Render"},
		{"fly.toml", "Fly.io"},
	}

	for _, c := range ciChecks {
		if scan.HasFile(files, c.file) || scan.HasFileAnywhere(files, c.file) {
			matches = append(matches, Match{Name: c.name, Category: CI, Confidence: 1.0, Evidence: []string{c.file}})
		}
	}

	return matches
}

func detectBundlers(files []scan.FileInfo) []Match {
	var matches []Match

	checks := []struct {
		file string
		name string
	}{
		{"webpack.config.js", "Webpack"},
		{"webpack.config.ts", "Webpack"},
		{"vite.config.ts", "Vite"},
		{"vite.config.js", "Vite"},
		{"rollup.config.js", "Rollup"},
		{"rollup.config.mjs", "Rollup"},
		{"esbuild.config.js", "esbuild"},
		{"tsup.config.ts", "tsup"},
		{"turbo.json", "Turborepo"},
	}

	for _, c := range checks {
		if scan.HasFile(files, c.file) {
			matches = append(matches, Match{Name: c.name, Category: Bundler, Confidence: 1.0, Evidence: []string{c.file}})
		}
	}

	return matches
}

func detectInfra(files []scan.FileInfo) []Match {
	var matches []Match

	checks := []struct {
		file string
		name string
	}{
		{"Dockerfile", "Docker"},
		{"docker-compose.yml", "Docker Compose"},
		{"docker-compose.yaml", "Docker Compose"},
		{"compose.yml", "Docker Compose"},
		{"Makefile", "Make"},
		{"Taskfile.yml", "Task"},
		{"terraform.tf", "Terraform"},
		{"pulumi.yaml", "Pulumi"},
		{"serverless.yml", "Serverless Framework"},
		{"wrangler.toml", "Cloudflare Workers"},
		{"k8s.yaml", "Kubernetes"},
	}

	for _, c := range checks {
		if scan.HasFile(files, c.file) || scan.HasFileAnywhere(files, c.file) {
			matches = append(matches, Match{Name: c.name, Category: Infra, Confidence: 1.0, Evidence: []string{c.file}})
		}
	}

	return matches
}

func detectStyling(root string, files []scan.FileInfo) []Match {
	var matches []Match

	if scan.HasFile(files, "tailwind.config.js") || scan.HasFile(files, "tailwind.config.ts") {
		matches = append(matches, Match{Name: "Tailwind CSS", Category: Styling, Confidence: 1.0, Evidence: []string{"tailwind config"}})
	}

	// check package.json
	if scan.HasFile(files, "package.json") {
		pkg, _ := scan.ReadFileHead(root, "package.json", 8192)
		styleChecks := []struct {
			dep  string
			name string
		}{
			{"tailwindcss", "Tailwind CSS"},
			{"styled-components", "styled-components"},
			{"@emotion", "Emotion"},
			{"sass", "Sass"},
			{"less", "Less"},
			{"@mui/material", "Material UI"},
			{"@chakra-ui", "Chakra UI"},
			{"@radix-ui", "Radix UI"},
			{"shadcn", "shadcn/ui"},
		}
		for _, c := range styleChecks {
			if strings.Contains(pkg, `"`+c.dep+`"`) {
				matches = append(matches, Match{Name: c.name, Category: Styling, Confidence: 0.9, Evidence: []string{"package.json"}})
			}
		}
	}

	if scan.HasExt(files, "scss") {
		matches = append(matches, Match{Name: "Sass", Category: Styling, Confidence: 0.8, Evidence: []string{".scss files"}})
	}

	return matches
}

func detectRuntime(files []scan.FileInfo) []Match {
	var matches []Match

	checks := []struct {
		file string
		name string
	}{
		{".nvmrc", "Node.js (nvm)"},
		{".node-version", "Node.js"},
		{".python-version", "Python"},
		{".ruby-version", "Ruby"},
		{".tool-versions", "asdf"},
		{"deno.json", "Deno"},
		{"deno.jsonc", "Deno"},
	}

	for _, c := range checks {
		if scan.HasFile(files, c.file) {
			matches = append(matches, Match{Name: c.name, Category: Runtime, Confidence: 1.0, Evidence: []string{c.file}})
		}
	}

	return matches
}
