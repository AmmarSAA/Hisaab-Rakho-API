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

The Hisaab-Rakho-2.0 Flutter client uses this private API and is published at
https://hisaab-rakho-ammarsaa.netlify.app. It uses expiring sessions and the account
recovery flow; browser refresh requires sign-in because web tokens stay in memory.
HisaabRakho remains a separate local demonstration.

## Recovery and email delivery

POST /auth/recover with JSON `{ "email": "account@example.com" }` returns the
same HTTP 202 message for known and unknown accounts. Rate limits prevent repeated
requests. An existing account receives a single-use link to `/reset#<token>`;
the token expires in 30 minutes and its hash is stored in D1. POST /auth/reset
accepts `{ "token": "...", "password": "..." }`, consumes the token, replaces the
password hash, unlocks the account and revokes prior sessions. Passwords must
contain at least 12 characters.

The Worker owns recovery state and sends email requests to a separate Netlify
function, `/api/recovery-mail`. That function uses Nodemailer and a TLS SMTP
connection. Requests are authenticated with an HMAC-SHA256 signature over the
timestamp and exact JSON body; the relay checks freshness and rejects replays.
The browser never receives SMTP credentials or the relay secret.

Configure these Worker bindings securely:

- `RECOVERY_RELAY_URL`: the HTTPS Netlify `/api/recovery-mail` URL.
- `RECOVERY_RELAY_SECRET`: a shared random secret of at least 32 characters,
  also configured privately on the Netlify relay.
- `PUBLIC_BASE_URL`: the HTTPS Worker origin used in recovery links.
- `ALLOWED_ORIGINS`: exact trusted frontend origins, separated by commas.

Configure the relay's SMTP host, port, user, password, sender address and shared
relay secret in Netlify environment variables. Use port 465 with implicit TLS or
587 with required STARTTLS. Never put credentials in source, Flutter assets,
public build variables or logs. `worker/mailer.mjs` is the independently tested
Nodemailer mail implementation; the Worker itself uses `worker/mail-relay.mjs`
and does not import the Node SMTP transport.

## Development and deployment

Use Node 24 or newer. npm install; npm test; npm run dev. Initialize the local
D1 schema with npx wrangler d1 migrations apply hisaab-private --local. Deployment
uses npm run deploy and the account/database IDs in wrangler.jsonc. npm test
exercises authentication, ownership isolation, filters, validation, expiry,
logout, CORS and persistence using an actual SQLite database adapter.

The checked-in ALLOWED_ORIGINS permits the configured Netlify frontend and the
existing GitHub frontend origin. Native clients have no browser Origin header.
Other browser origins are rejected; same-origin Worker reset requests are allowed.

## Private migration

scripts/migrate-private.mjs accepts a local historical JSON database and output
path. Its ignored .private-migration.json file contains parameterized inserts,
locked salted hashes and financial records; never commit or publish it. Apply
it only to a fresh private D1 database using authenticated account access.
Historical backups in Git history remain exposed and require a separate
repository cleanup; no public financial export is deployed with this Worker.
