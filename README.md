# TOPSTORIES.WORLD

A responsive editorial publication with a React/Vite frontend, Express API, and PostgreSQL persistence.

## Requirements

- Node.js 22 or newer and npm
- Docker with the Compose plugin

## First-time setup

Create a local environment file and replace its passwords/secrets with unique values. The database password should be URL-safe (hex works); the JWT secret must have at least 32 characters. Keep `.env` private; it is ignored by Git and excluded from the Docker build context.

```sh
cp .env.example .env
```

PowerShell equivalent: `Copy-Item .env.example .env`. Generate strong values with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`.

## Local development

Start PostgreSQL, install dependencies, then run the API and Vite together:

```sh
docker compose up -d db
npm ci
npm run dev
```

The site is at `http://localhost:5173`; the API health check is `http://localhost:3000/api/health`. The Vite development server proxies `/api` to Express. For local HTTP, set `COOKIE_SECURE=false`. The API creates its schema and starter articles on first startup.

If the full Compose app is already using port 3000, stop it before starting the host dev processes with `docker compose stop app`; PostgreSQL stays up on `127.0.0.1:5432`.

## Full container deployment

Set unique values in `.env` for `POSTGRES_PASSWORD`, `JWT_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`, then run:

```sh
docker compose up --build -d
```

The app is served on `http://localhost:3000`. For a public HTTPS deployment, set `COOKIE_SECURE=true`, use a strong JWT secret, terminate TLS at a trusted reverse proxy, and set the origin/environment values to the production host. Back up the `postgres_data` volume regularly. `docker compose down` stops the services; use `docker compose down -v` only when you intend to permanently erase the database volume.

## Public frontend and API deployment

Deployment manifests are included for Vercel (`vercel.json`) and Render (`render.yaml`). Vercel serves the Vite SPA and rewrites direct article/category URLs to the client app. Render runs Express with managed PostgreSQL; startup applies additive migrations and upserts the source-linked November 2026 editorial feed.

For Vercel, import the repository and set `VITE_API_BASE_URL` to the public Render API origin (for example, `https://topstories-world-api.onrender.com`). For Render, provide the exact Vercel production origin as `CLIENT_ORIGIN`, and set `ADMIN_EMAIL` / `ADMIN_PASSWORD`. The blueprint enables HTTPS-only `SameSite=None` cookies for cross-origin frontend/API sessions and generates the JWT secret. Keep API and frontend origins aligned. Cookie authentication uses credentialed CORS.

The source directory must be pushed to a Git provider before either host can import it. Do not place `.env` or production secrets in Git. Review the Render service and database plan and current pricing before creating cloud resources.

## Authentication and roles

- Reader accounts are created through **Your reading room → Create account**. Passwords must be at least 12 characters and are stored as bcrypt hashes.
- Login issues a 15-minute JWT in an HttpOnly, SameSite=Lax cookie. Protected routes also accept `Authorization: Bearer <token>`. The API applies rate limits, CORS allowlisting, security headers, request validation, and parameterized SQL.
- New accounts always receive the `reader` role. Readers can save stories, like articles, and comment. Only server-authorized `editor` and `admin` roles can create or publish articles; deletion is also role protected.
- The account configured by `ADMIN_EMAIL` and `ADMIN_PASSWORD` is bootstrapped as `admin`. Additional editor access must be assigned through a trusted database/admin process; there is no public role-escalation endpoint.
- In this workspace, the initial administrator email/password are stored only in the ignored `.env` file. Read those values locally to sign in; do not commit or share the file.

## API overview

- `POST /api/auth/signup`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET/PATCH /api/auth/me`
- `GET /api/articles?category=Science&sort=Latest&q=...`, `GET /api/articles/:id`, article comments, likes, and view count routes
- `GET/POST/DELETE /api/bookmarks` (sign-in required; `/api/me/bookmarks` is retained as an alias)
- `GET /api/me/history` returns the signed-in reader's recent reading history
- `POST /api/newsletter` stores a normalized subscriber address idempotently
- `GET/POST/PATCH/DELETE /api/admin/articles` (editor/admin authorization)

## Client routes

- `/` — front page and editorial feed
- `/category/:slug` — category feed with Latest, Popular, and Trending sorting
- `/article/:id` — long-form story, source attribution, discussion, likes, and bookmarks
- `/profile` — saved stories and reading history
- `/auth/login` and `/auth/signup` — dedicated reader account screens
- `/admin` — role-protected publishing dashboard

The API reflects credentialed CORS only for the configured `CLIENT_ORIGIN` / `APP_CLIENT_ORIGIN` and the local development origins `http://localhost:5173` and `http://localhost:3000`. Add the exact production frontend origin to the environment before deployment. PostgreSQL startup migrations create users, articles, comments, likes, bookmarks, reading history, and newsletter subscribers with foreign keys where applicable. Source-linked seed stories are upserted idempotently by source URL at startup, and generic placeholder rows are removed.

## Build and checks

```sh
npm run build
docker compose config
```

The hero and story image frames retain their dimensions and show editorial gradients if an external image fails to load. Story content is database-backed with no local sample-article fallback; sourced stories include author biographies and source attribution.
