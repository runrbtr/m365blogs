# M365Blogs (Post Stream)

**https://m365blogs.runr.is** — one page for every new post on five blogs. Reading is open to everyone; create a
free account to keep favorites and a "new since last visit" marker across browsers and devices.

(Change the address any time — see [Changing the address](#changing-the-address).)

| Blog | Feed used |
|---|---|
| [Peter van der Woude](https://petervanderwoude.nl/) | https://petervanderwoude.nl/feed/ |
| [Patch My PC](https://patchmypc.com/blog/) | https://patchmypc.com/blog/feed/ |
| [Andrew Taylor](https://andrewstaylor.com/) | https://andrewstaylor.com/feed/ |
| [Prajwal Desai](https://www.prajwaldesai.com/blog/) | https://www.prajwaldesai.com/feed/ |
| [Call4Cloud](https://call4cloud.nl/) | https://call4cloud.nl/feed/ |

Nothing else is contacted.

## Deploying (GitHub → Traefik, like `password-generator`)

Same shape as your `password-generator` project: push to `main`, GitHub Actions builds and pushes the image to
GHCR, and `docker-compose.yml` on the host pulls it and lets Traefik route to it. `docker-compose.yml` here needs no
editing for that to work; it already points at `ghcr.io/runrbtr/post-stream`.

1. **Create the GitHub repo** and push this folder (`data/` and `.env` are gitignored, so runtime data and secrets
   never get committed):

   ```bash
   git init && git add -A && git commit -m "Post Stream"
   git branch -M main
   git remote add origin git@github.com:runrbtr/post-stream.git
   git push -u origin main
   ```

   The workflow at `.github/workflows/docker-publish.yml` runs the test suite on every push and pull request, and on
   `main` also builds and pushes `ghcr.io/runrbtr/post-stream:latest`. It needs no secrets: `GITHUB_TOKEN` is
   automatic. After the first push, make the package public (or keep it private and
   `docker login ghcr.io` on the host) — GitHub → your profile → Packages → post-stream → Package settings.

2. **On the Docker host**, next to your `password-generator` compose file, in a new folder:

   ```bash
   docker network create external_access   # skip if it already exists (password-generator made it)
   ```

   Copy `docker-compose.yml` there (that's the only file the host needs). Add a DNS record for
   `m365blogs.runr.is` pointing at the host, same as `lykilord.runr.is`.

   ```bash
   docker compose pull
   docker compose up -d
   ```

   The `cloudflare` cert resolver, entrypoints and network are the ones your Traefik already has, matching
   `password-generator`'s compose file.

3. **Everyone can now sign in or create their own account** at https://m365blogs.runr.is/signup — see
   [Accounts](#accounts). If you'd rather create the first one yourself from the shell:

   ```bash
   docker compose exec post-stream python app.py adduser YOURNAME
   ```

Update to a new build: `docker compose pull && docker compose up -d` (or wire up Watchtower/Diun, if that's what
you use for `password-generator`).

### Changing the address

Create a `.env` file next to `docker-compose.yml` on the host (copy `.env.example`):

```
POSTSTREAM_HOST=posts.runr.is
```

then `docker compose up -d`. This changes both the Traefik routing rule and the `PUBLIC_URL` the app uses to
validate sign-in requests, so change it there rather than editing the compose file directly.

## Accounts

- **Reading needs no account.** Anyone with the link can browse, search and filter.
- **Sign-up is self-service and open by default** — no invite, no email. There's a honeypot field and a per-address
  limit (5 sign-ups/hour) against bots, but nothing stops a person from making one. Set `ALLOW_SIGNUP=0` in `.env` to
  close sign-up while keeping existing accounts (you can still add people with `adduser`). `MAX_USERS` (default
  1000) is a second cap if you leave it open.
- **No email, so no password reset or recovery.** A forgotten password can only be reset by whoever runs the
  container:

  ```bash
  docker compose exec post-stream python app.py passwd NAME     # asks for a new password, signs them out everywhere
  docker compose exec post-stream python app.py deluser NAME    # delete a user and their favorites
  docker compose exec post-stream python app.py users           # list users and their favorite counts
  ```
- Favorites and the read marker are private to each account; nobody else can see them through the site.

## What is protected, and what is not

- Passwords are stored as salted PBKDF2-SHA256 (600,000 rounds). Sessions are random tokens stored only as hashes,
  last 30 days, and are cleared on sign-out or password change. The cookie is `HttpOnly`, `SameSite=Lax`, and
  `Secure` once served over HTTPS (which Traefik handles here).
- Failed logins are limited to 8 per address / 30 per username per 10 minutes; sign-ups to 5 per address per hour.
  Counters are in memory and reset on restart.
- Strict Content-Security-Policy (no inline scripts), `X-Robots-Tag: noindex` and `/robots.txt` keep it out of
  search engines, and state-changing requests from other sites are rejected.
- The container runs as an unprivileged user with a read-only filesystem, no extra capabilities, and publishes no
  port directly — only Traefik can reach it (see `docker-compose.yml`).
- Not included: two-factor sign-in or email verification.

## How it works

- `build.py` fetches the feeds (paging `?paged=N` for history on first run, then only the newest page), merges the
  same article when it appears on several blogs, and writes one HTML page. Call4Cloud's feed serves most posts from
  `patchmypc.com`, so those show once, labelled with both blogs.
- `app.py` serves that page (publicly), a login/sign-up flow, and a small JSON API for favorites and the read
  marker, and re-runs the build on a timer. `store.py` is the SQLite storage (users, sessions, favorites).
- The generated page is the same for everyone; a signed-in visitor's favorites and marker load from the server
  after the page loads, and refresh when you return to an idle tab.
- Only posts that exist in the archive can be favorited. The archive is never trimmed, and the page shows the newest
  2000 posts.

## Local development

```bash
docker compose -f docker-compose.dev.yml up -d --build   # http://127.0.0.1:8080, loopback only
docker compose -f docker-compose.dev.yml exec post-stream python app.py adduser you
```

Or without Docker:

```bash
python3 app.py adduser you
python3 app.py serve             # http://127.0.0.1:8766, data in ./data
```

Without `pip install waitress`, this uses Python's built-in server — fine for trying it out, not for hosting.

### Tests

```bash
python3 -m unittest discover -s tests -v
```

Covers public reading, login, sign-up (including the honeypot and rate limits), lockout, session cookies,
cross-site request blocking, per-user isolation of favorites, input validation and account deletion. These run in
CI on every push and pull request.

## Backups

Stop the container first so the database is consistent, then archive the volume:

```bash
docker compose stop
docker run --rm -v post-stream_poststream-data:/data -v "$PWD":/backup alpine tar czf /backup/poststream-backup.tgz -C /data .
docker compose start
```

(Volume name is `<folder name>_poststream-data` — check with `docker volume ls`.)

## Settings (`.env`, see `.env.example`)

| Variable | Default | Meaning |
|---|---|---|
| `POSTSTREAM_HOST` | `m365blogs.runr.is` | The address Traefik routes and the app validates sign-in requests against |
| `ALLOW_SIGNUP` | `1` | `0` closes self-service sign-up |
| `MAX_USERS` | `1000` | Stop accepting sign-ups beyond this many accounts |

Less commonly changed, set directly in `docker-compose.yml`: `REFRESH_MINUTES` (how often to check the blogs),
`TRUST_PROXY` (must stay `1` here — the app is only reachable through Traefik). Change the blog list itself in
`SOURCES` in `build.py` (any WordPress blog works: use its `/feed/` URL).
