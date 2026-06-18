# caretext

Architecture notes live in [docs/architecture.md](docs/architecture.md).

## Cloudflare App Scaffold

This repo now includes a Cloudflare Workers + D1 scaffold for:

- Username/password registration and login.
- Google OAuth server-flow login.
- User profile storage.
- Up to 10 recipient phone numbers per user.
- Recipient taxonomy settings using the categories in `docs/architecture.md`.
- Frequencies: `daily`, `weekly`, and `every_other_week`.

### Local Setup

```bash
npm install
copy .dev.vars.example .dev.vars
npx wrangler d1 migrations apply caretext-db --local
npm run dev
```

Then open:

- Marketing hero: `http://127.0.0.1:8787/`
- App scaffold: `http://127.0.0.1:8787/app.html`

### Google OAuth

Create OAuth credentials in Google Cloud Console and set the authorized redirect URI to:

```text
http://127.0.0.1:8787/api/auth/google/callback
```

For production, add the production equivalent:

```text
https://YOUR_DOMAIN/api/auth/google/callback
```

Store secrets in `.dev.vars` locally:

```text
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
SESSION_SECRET=...
```

For production, use Wrangler secrets:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put SESSION_SECRET
```

### D1 Production Setup

Create the production database:

```bash
npx wrangler d1 create caretext-db
```

Copy the returned `database_id` into `wrangler.jsonc`, then apply migrations:

```bash
npx wrangler d1 migrations apply caretext-db --remote
```
