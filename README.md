# stackscan

Detect the tech stack of any project from your terminal.

Point it at a directory, get back everything: languages, frameworks, databases, package managers, CI/CD, testing, linting, infrastructure.

```
$ stackscan .

  stackscan my-project
  34 files scanned in 2ms

  Languages
    ● TypeScript    ts, tsx files found
    ● JavaScript    js, jsx, mjs, cjs files found

  Frameworks & Libraries
    ● Next.js       package.json dependency
    ● React         package.json dependency

  Databases & Storage
    ● PostgreSQL    docker-compose.yml
    ● Redis         docker-compose.yml

  Package Managers
    ● npm           package.json

  Build Tools
    ● Vite          vite.config.ts

  Styling
    ● Tailwind CSS  tailwind config

  Testing
    ● Vitest        vitest.config.ts

  Linting & Formatting
    ● ESLint        eslint.config.mjs
    ● Prettier      .prettierrc

  CI/CD & Deployment
    ● GitHub Actions .github/workflows/ci.yml
    ● Vercel        vercel.json

  Infrastructure
    ● Docker        Dockerfile
    ● Docker Compose docker-compose.yml
```

## Install

```
go install github.com/am0y/stackscan/cmd/stackscan@latest
```

Or build from source:

```
git clone https://github.com/am0y/stackscan.git
cd stackscan
go build -o stackscan ./cmd/stackscan/
```

## Usage

```
stackscan [flags] [path]
```

| Flag | Description |
|------|-------------|
| (none) | Pretty table output |
| `-json` | JSON output |
| `-compact` | One line per category |
| `-version` | Print version |

```
stackscan .                    # current directory
stackscan ~/projects/my-app    # any path
stackscan -json .              # pipe to jq, scripts, etc.
stackscan -compact .           # quick overview
```

## What it detects

150+ technologies across 11 categories.

**Languages** — Go, Rust, TypeScript, JavaScript, Python, Ruby, Java, Kotlin, Swift, C#, C++, C, PHP, Dart, Elixir, Zig, Lua, Scala, R, Shell

**Frameworks** — Next.js, Nuxt, React, Vue, Svelte, SvelteKit, Angular, Express, Fastify, Hono, NestJS, Astro, Remix, Gatsby, Electron, React Native, Expo, Django, Flask, FastAPI, Gin, Fiber, Echo, Chi, Actix Web, Axum, Rocket, Rails, Sinatra, Flutter, Tauri, Bubble Tea

**Databases** — PostgreSQL, MySQL, MariaDB, MongoDB, Redis, SQLite, Supabase, Firebase, Elasticsearch, Meilisearch, ClickHouse, MinIO, RabbitMQ, NATS

**ORMs** — Prisma, Drizzle, GORM, Mongoose, Sequelize, SQLAlchemy

**Package Managers** — npm, Yarn, pnpm, Bun, Go Modules, Cargo, pip, Pipenv, Poetry, Bundler, Composer, Gradle, Maven, Swift PM, Pub, Mix

**Build Tools** — Vite, Webpack, Rollup, esbuild, tsup, Turborepo

**Testing** — Jest, Vitest, Cypress, Playwright, Mocha, Testing Library, AVA, pytest, PHPUnit, Go testing

**Linting** — ESLint, Prettier, Biome, golangci-lint, rustfmt, Clippy, RuboCop, Flake8, mypy, Stylelint, EditorConfig

**CI/CD** — GitHub Actions, GitLab CI, Jenkins, CircleCI, Travis CI, Vercel, Netlify, Railway, Render, Fly.io

**Infrastructure** — Docker, Docker Compose, Terraform, Pulumi, Kubernetes, Cloudflare Workers, Serverless Framework, Make, Task

**Styling** — Tailwind CSS, Sass, Less, styled-components, Emotion, Material UI, Chakra UI, Radix UI, shadcn/ui

## How it works

stackscan walks the file tree (skipping `node_modules`, `.git`, `vendor`, etc.) and builds a list of filenames and extensions. Then it runs detectors against that list:

- **File presence** — `Dockerfile` → Docker, `go.mod` → Go Modules
- **Extension counting** — `.ts` files → TypeScript (confidence scales with count)
- **Dependency parsing** — reads `package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`, `Gemfile` for specific packages
- **Config sniffing** — checks `docker-compose.yml` for database images, `.env.example` for connection strings

Each match gets a confidence score (0.5–1.0). The colored dots in table output reflect this: green = high, yellow = medium, dim = inferred.

Zero network requests. Zero dependencies. Just file system reads.

## License

MIT
