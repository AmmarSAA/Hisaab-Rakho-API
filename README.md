# Hisaab Rakho private API

Production: https://hisaab-private-api.s-ammarahmed14.workers.dev

Cloudflare Workers provides the API; D1 stores records persistently. All user and
transaction routes require an expiring Bearer session. The old unauthenticated
JSON Server handler now returns HTTP 410.

## Authentication

POST /auth/register with JSON email, password (at least 12 characters), and
optional name creates an account. POST /auth/login with email and password
returns { token, expires_at, user }. Sessions expire after one hour. Send
Authorization: Bearer <token> with subsequent requests. POST /auth/logout
revokes that session. GET /auth/me returns the signed-in profile and totals.
Passwords and password hashes are never returned.

## Data routes

GET /users and GET /users/:id return only the authenticated user. GET
/transaction and GET /transaction/:id return only their transactions. Supported
filters are id and user_id; they never override session ownership. POST
/transaction, PATCH or PUT /transaction/:id, and DELETE /transaction/:id operate
only on that user's records. Transaction input requires amount and income on
creation. Amount accepts a finite nonnegative number or a plain decimal string.
PATCH /users/:id permits only name, avatar, currency_symbol, currency_name,
and gender. Database exports and legacy password lookup are disabled.

## Existing accounts

The six imported accounts are locked because their historical passwords were
committed to the old public repository. The 27 imported transactions are retained
in D1 and isolated by their original owner IDs. Hashing those compromised
passwords would not protect the accounts. Verified password recovery is needed
before imported accounts may sign in. Do not restore historical credentials.

The Flutter Hisaab-Rakho-2.0 client still uses a legacy Railway URL and compares
passwords obtained from GET /users. It must change to /auth/login, store the
returned session, send Authorization on API calls, and stop storing passwords.
Its old login flow intentionally cannot work against this API. HisaabRakho is a
separate local demonstration. This change does not deploy those Flutter apps.

## Development and deployment

Use Node 24 or newer. npm install; npm test; npm run dev. Initialize the local
D1 schema with npx wrangler d1 migrations apply hisaab-private --local. Deployment
uses npm run deploy and the account/database IDs in wrangler.jsonc. npm test
exercises authentication, ownership isolation, filters, validation, expiry,
logout, CORS and persistence using an actual SQLite database adapter.

ALLOWED_ORIGINS is empty by default: native clients work; browser calls from an
Origin are denied until an exact trusted frontend origin is configured.

## Private migration

scripts/migrate-private.mjs accepts a local historical JSON database and output
path. Its ignored .private-migration.json file contains parameterized inserts,
locked salted hashes and financial records; never commit or publish it. Apply
it only to a fresh private D1 database using authenticated account access.
Historical backups in Git history remain exposed and require a separate
repository cleanup; no public financial export is deployed with this Worker.
