**Live demo:** https://swan-leads.onrender.com/
Login: demo@swan.test / Demo@1234

# Swan Leads — Lead Management System

Full-stack lead tracker for a digital marketing company: authentication, lead CRUD, dashboard with charts, search/filter/pagination, CSV export and role-based access.

## Tech stack
- **Backend:** Node.js 18+, Express, SQLite (better-sqlite3)
- **Auth/security:** bcrypt (12 rounds), JWT in an httpOnly SameSite cookie, helmet (CSP + headers), rate limiting on login/register, parameterised SQL, server-side validation, CSV formula-injection guard
- **Frontend:** Vanilla JS single page app (no build step), Chart.js, responsive CSS with dark mode. Served by the same Express server, so there is one deployment and no CORS.

## Features
- Register, login, logout; protected dashboard and API
- Lead CRUD with all required fields and statuses (New, Contacted, Qualified, Converted, Lost)
- Dashboard: total + per-status counts, status doughnut chart, 14-day new-leads bar chart
- Search (name/email/phone), status filter, created-date range filter, pagination
- Bonus: Admin/Sales roles (first registered user is admin and sees all leads; others see only their own), CSV export respecting filters, loading/error/empty states, Dockerfile

## Setup
```bash
npm install
cp .env.example .env     # set JWT_SECRET to a long random string
npm start                # http://localhost:3000
```
Docker: `docker build -t swan-leads . && docker run -p 3000:3000 -e JWT_SECRET=... -e SEED_DEMO=true -v leads-data:/data swan-leads`

## Environment variables
| Name | Purpose |
|---|---|
| `JWT_SECRET` | Required, 16+ chars. Signs session tokens |
| `PORT` | Default 3000 |
| `NODE_ENV` | `production` enables secure cookies (needs HTTPS) |
| `DB_PATH` | SQLite file path (default `./data/leads.db`) |
| `SEED_DEMO` | `true` creates the demo user and sample leads on an empty database |

## Demo credentials (when `SEED_DEMO=true`)
`demo@swan.test` / `Demo@1234` (admin)

## API
All `/api/leads*` routes require the auth cookie. Errors return `{ "error": "...", "details": {...} }`.

| Method | Path | Description | Success |
|---|---|---|---|
| POST | `/api/auth/register` | `{name,email,password}` | 201 |
| POST | `/api/auth/login` | `{email,password}` | 200 |
| POST | `/api/auth/logout` | Clears cookie | 204 |
| GET | `/api/auth/me` | Current user | 200 |
| GET | `/api/leads` | Query: `q,status,from,to,page,limit` | 200 |
| GET | `/api/leads/stats` | Counts per status + daily series | 200 |
| GET | `/api/leads/export.csv` | CSV, same filters as list | 200 |
| GET | `/api/leads/:id` | One lead | 200 / 404 |
| POST | `/api/leads` | Create | 201 / 400 |
| PUT | `/api/leads/:id` | Update | 200 / 400 / 404 |
| DELETE | `/api/leads/:id` | Delete | 204 / 404 |

Other codes: 401 unauthenticated, 409 duplicate email, 429 rate limited.

## Database
SQLite, two tables. `users(id, name, email UNIQUE, password_hash, role, created_at)` and `leads(id, user_id → users ON DELETE CASCADE, name, email, phone, company, service, status CHECK(...), follow_up_date, notes, created_at)`, indexed on `(user_id, status)` and `created_at`. Tables are created automatically on startup.

## Deployment (Render, free tier)
1. Push to GitHub (`.env` and `*.db` are git-ignored).
2. Render → New Web Service → connect the repo. Build: `npm install`. Start: `npm start`.
3. Set env vars: `JWT_SECRET`, `NODE_ENV=production`, `SEED_DEMO=true`. For persistent data, attach a disk and set `DB_PATH=/var/data/leads.db`; without one, SQLite resets on redeploy.
4. Submit the Render URL (frontend and API share it), the repo link and the demo credentials.
