# mPass SSO (oauth2-proxy ForwardAuth)

How this fork authenticates on the Moneta FOSS platform, what a deployment has to provide,
and what Layer 2 needs to wire it into the bundle.

Activated by `AUTH_TYPE=SSO`. Unset, every path below is inert and Mautic behaves like
upstream: local login, password reset and the installer work as shipped.

## How it works

Mautic never talks to the identity provider. Traefik asks oauth2-proxy (`mpass-auth`) whether
each admin-UI request carries a valid mPass session; if not, the browser goes through the mPass
QR login and comes back. Requests that reach Mautic carry the user's identity in
`X-Auth-Request-*` headers.

```text
browser ──> traefik ──(ForwardAuth, admin UI and API)──> oauth2-proxy ──> mpass-auth-proxy ──> Cognito
               │
               └─ request + X-Auth-Request-* ──> mautic (MpassProxyAuthenticator on the `main` firewall)
```

`MpassProxyAuthenticator` (a Symfony authenticator on the `main` firewall, `^/(s/|elfinder|efconnect)`)
reads `X-Auth-Request-Email` on every request:

- **Match** with the session's user: nothing happens.
- **No session:** the user is resolved by exact email match, or created (see Provisioning), and
  logged in.
- **Different identity:** the old session is invalidated first, then the new user is logged in.
  Remember-me is disabled under SSO and its cookie is expired, so the old user cannot come back.
- **Header absent:** not a logout signal (internal traffic carries none); the request proceeds on
  whatever session it has.

Mautic's native SAML is not used under SSO; the platform relies on the header contract only.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `AUTH_TYPE` | yes | `SSO` turns the integration on. Read per request from the environment, never from a Mautic config key |
| `DEFAULT_EMAIL_DOMAIN` | yes | Domain for a bare mPass id (`<id>@<domain>`). Unset, every bare-id login is refused. Must match the other bundle apps |
| `LOGOUT_REDIRECT_URL` | yes | The portal the user menu's Logout navigates to. Must be an absolute `http(s)` URL; otherwise it is logged and Logout shows a static page instead of redirecting |
| `SESSION_COOKIE_MAX_AGE_SECONDS` | no | Mautic session lifetime (`session.gc_maxlifetime`, `session.cookie_lifetime`, and the idle check). Default `432000`, the platform's. Must be a positive integer |
| `SMB_CORPORATE_ID` | one of these two | Only principals whose access token has `custom:is_corporate=true` and this `custom:corporate_id` are admitted |
| `MPASS_ALLOW_ANY_TENANT` | | `1` admits every mPass principal when `SMB_CORPORATE_ID` is unset. See [Trade-offs](#trade-offs) |
| `MPASS_SSO_DEFAULT_ROLE` | no | Role id new SSO users get. Unset: the role named `mPass Member`, which the image creates at boot. Must be a published, non-admin role |
| `MPASS_EDGE_SECRET` / `MPASS_EDGE_SECRET_FILE` | no | Optional edge secret; see [Header trust](#header-trust) |
| `MAUTIC_SITE_URL` | yes | The https URL users see. Written to `site_url` |
| `MAUTIC_DB_HOST`, `MAUTIC_DB_PORT` (3306), `MAUTIC_DB_NAME`, `MAUTIC_DB_USER`, `MAUTIC_DB_PASSWORD` | yes | MariaDB/MySQL connection, used for the install |
| `TRUSTED_PROXIES` | yes behind Traefik | Comma-separated CIDRs Traefik's requests come from, so `X-Forwarded-Proto` and the client IP are honoured |
| `TRUSTED_HOSTS` | no | Comma-separated host regexes. Default: the `MAUTIC_SITE_URL` host |

Not `MAUTIC_TRUSTED_*`: Mautic maps every config key `K` to an `MAUTIC_<K>` env override and
parses it as JSON, which `TrustMiddleware` ignores.

## Header trust

Header trust is topology-based, the same as every bundle app:

1. Mautic's port is never published; Traefik is the only way in.
2. Every Mautic router runs `strip-auth-headers` first, so a client cannot inject
   `X-Auth-Request-*`; on the protected router `mpass-auth` then sets the verified values.
3. oauth2-proxy validates the upstream session on every ForwardAuth call.

**Optional edge secret.** Topology trust does not cover another container on the same Docker
networks, which can reach Apache directly with any header. Setting `MPASS_EDGE_SECRET`
(at least 32 characters) closes that: the protected router adds `X-Mpass-Edge-Secret` with the
value, every other Mautic router strips a client copy, and Mautic then trusts identity headers
only on a request carrying it (constant-time compare). Admin-UI requests without it get `403`.
The image moves the value into a root-owned file (`MPASS_EDGE_SECRET_FILE`) before Apache starts,
so `phpinfo()` and environment dumps cannot show it. Unset, Mautic trusts topology, as the
platform contract describes.

Mautic's own outbound HTTP cannot be used to forge headers either way: under SSO,
`MpassOutboundGuard` keeps the campaign "Send a webhook" action and form "repost" off private,
loopback and other special-purpose addresses (IPv4-mapped IPv6 unwrapped), pins the resolved
address and never follows redirects.

## Trade-offs

- **Tenant binding fails closed.** The contract skips the corporate check when
  `SMB_CORPORATE_ID` is unset. This fork refuses every login in that case unless
  `MPASS_ALLOW_ANY_TENANT=1`, and the image refuses to start. Reason: Mautic holds the contact
  database, and an empty variable silently admitting the whole Cognito pool is the easy mistake.
  Cost: on a non-corporate deployment, Layer 2 must set `MPASS_ALLOW_ANY_TENANT=1`.
- **Last name is a filler.** Mautic requires both name fields, and the mPass identity carries no
  name. A new user gets the part of the email before `@` as first name and `-` as last name, so a
  bare-id user shows as `1020010000019120 -`. Names are set only at creation; users edit both in
  Account settings, and later logins keep the edit.
- **No password for anyone.** SSO users get a random, discarded password. The install admin is a
  placeholder (`mautic-install@admin.invalid`) whose password is discarded too. Admins come only
  from `/opt/mautic-users.php grant-admin`.
- **Upstream footprint.** About 210 changed lines across 13 upstream files, two of them upstream
  tests updated for the guard and the outbound guard (largest:
  `UserController.php`, which drops password and email fields under SSO). Moving that into a form
  extension would make rebases cheaper; not done yet.

## Provisioning

- Identity is `X-Auth-Request-Email` only (`X-Auth-Request-User` is the Cognito `sub` and is never
  read), trimmed and lowercased. A value with an `@` (not first) and a `.` at least one character
  after it is used as is; a bare value becomes `<value>@${DEFAULT_EMAIL_DOMAIN}`. The check is
  `strpos`-based, never a regex.
- Lookup is an exact match on `users.email`, never Mautic's `username OR email` user provider.
- A new user's first name is the part of the email before `@` (the mPass id for a bare value);
  the last name, which Mautic requires, is a `-` filler. Both are set only when the user is
  created and never on later logins, so names a user edits in Account settings stick.
- A new user gets the default role (above), never an admin role; an existing user is never
  re-roled. A missing, admin or unpublished default role refuses the login (`403` page, no user
  created).
- Concurrent first logins: a unique-constraint failure falls back to a read.
- Unpublished users are refused.

## Local-credential surfaces under SSO

Refused with an empty `404` (route-name based, so `/index.php/<path>` and percent-encoded twins are
covered):

- password login (`/s/login_check`), password reset (`/passwordreset*`), user invites
  (`/invite/*`, `/s/users/invite`);
- SAML (`/s/saml/*`, `/saml/*`) and plugin SSO (`/s/sso_login*`);
- the OAuth2 authorize flow's password form (`/oauth/v2/authorize_login*`);
- the installer (`/installer*`; the image installs from the CLI);
- user and role management through the API (`/api/users*`, `/api/roles*`, `/api/v2/users*`, and
  the self/permission endpoints).

Also under SSO: `/s/login` shows a static mPass page (or goes to the dashboard with an identity),
the profile and admin user forms drop password and email changes, usernames are locked to the
email, and an `Authorization` header or `access_token` parameter on the admin UI is refused with
`401` (a bearer or basic login there would be a second way into the UI).
`MpassLocalAuthGuardTest::testRouteInventory` fails when a new route sets a credential or issues a
session without being gated or listed.

## REST API and OAuth2

Under SSO the API is internal-only, the platform standard for every app. On the public host
`/api/*` and `/oauth/v2/*` are behind `mpass-auth` (the `mautic-secure` router), so they need an
mPass session like the admin UI. API-token clients, such as MCP servers, call Mautic over the
internal network instead (`http://mautic` on the backend network), where Mautic's own `api`
firewall authenticates them with no identity headers involved. Whether the API is on is the
admin's Configuration setting (`api_enabled`, default off); the image does not override it.

Internal calls need two headers, as if they had come through Traefik:

- `Host: <site host>` (the host of `MAUTIC_SITE_URL`). `TRUSTED_HOSTS` defaults to that host
  only, so `Host: mautic` gets `400 Untrusted Host`.
- `X-Forwarded-Proto: https`. The OAuth2 routes are https-only, so without it
  `/oauth/v2/token` is a `404`. Mautic honours the header because the caller's address is in
  `TRUSTED_PROXIES`.

```bash
curl -X POST http://mautic/oauth/v2/token -H 'Host: mautic.example.com' -H 'X-Forwarded-Proto: https' \
  -d grant_type=client_credentials -d client_id=<public id> -d client_secret=<secret>
curl http://mautic/api/contacts -H 'Host: mautic.example.com' -H 'X-Forwarded-Proto: https' \
  -H 'Authorization: Bearer <access_token>'
```

Only the client-credentials grant works. An OAuth2 client an admin creates in Settings > API
Credentials allows the authorization-code, refresh-token and client-credentials grants (Mautic adds
client credentials only for an admin), never a password grant, but the authorization-code
flow cannot be used under SSO: `/oauth/v2/authorize` sends the user to `authorize_login`, its
password form, which returns `404` (`MpassLocalAuthGuard::GATED_ROUTES`). Basic auth also works
if an admin enables it, but SSO users have no usable password.

## Session lifetime

- `SESSION_COOKIE_MAX_AGE_SECONDS` sets PHP's session lifetime, and the authenticator also drops a
  session idle for longer (PHP's GC is probabilistic).
- Once the mPass session is gone, admin-UI requests (including the keep-alive) are stopped at
  ForwardAuth, so the Mautic session runs out. Under SSO, an admin-UI XHR rejected by the gateway
  (`401`, or a cross-origin redirect) reloads the tab once into the mPass login.
- Outside the admin UI the Mautic session is not honoured: its cookie is dropped before the session
  starts, so public pages always see an anonymous visitor (staff visits count as contact activity,
  and unpublished assets/previews are not served through public URLs).

## Logout

Logout in the user menu navigates to `LOGOUT_REDIRECT_URL` and clears nothing: the next admin-UI
request would re-establish the session from the identity header anyway. Ending the session is the
portal's "Log out of all apps". A missing or non-`http(s)` URL is logged and Logout shows a static
page.

## ForwardAuth bypass list

Source of truth for the `mautic-secure` / `mautic-public` routers. Two routers, because landing
pages are a catch-all slug (`/{slug}`) and cannot be allow-listed:

| Router | Rule | Middlewares |
|---|---|---|
| `mautic-secure` | `PathRegexp(^(/index\.php)?/(s(/\|$)\|elfinder\|efconnect\|installer\|api(/\|$)\|oauth(/\|$)))`, priority 20 | `strip-auth-headers`, `security-headers`, `mpass-auth` (+ the edge-secret injector when used) |
| `mautic-public` | everything else on the host, priority 10 | `strip-auth-headers`, `mautic-public-headers` (+ the edge-secret strip when used) |

`mautic-public-headers` is the devkit's `security-headers` set without `X-Frame-Options`. Public
forms are embedded "via iframe" (`/form/{id}`, `/form/embed/{id}`) and landing pages may be framed
on customer sites; `SAMEORIGIN` would break both, and Mautic sends no frame header of its own. The
admin UI keeps `SAMEORIGIN`.

Protected, and why:

| Path | Why |
|---|---|
| `/s/*` | The admin UI (`main` firewall), including `/s/keep-alive` and every admin XHR |
| `/elfinder*`, `/efconnect*` | The file manager, also on the `main` firewall |
| `/installer*` | 404 under SSO anyway; never public |
| `/api/*`, `/oauth/v2/*` | REST API and OAuth2: internal-only under SSO (see "REST API and OAuth2") |
| `/index.php/` twins of the above | Same routes through the front controller |

Public, and why (all anonymous by construction, since identity headers are stripped):

| Path | Why |
|---|---|
| `/{slug}`, `/page/preview/{id}/{objectType}` | Landing pages and shared page previews |
| `/mtc.js`, `/mtc`, `/mtc/event`, `/mtracking.gif`, `/mautic-essential.js`, `/mautic-tracking.js` | Website tracking, called from customer sites |
| `/dwc`, `/dwc/{objectAlias}`, `/focus/{id}.js`, `/focus/{id}/viewpixel.gif` | Dynamic Web Content and Focus items, called by `mtc.js` on external sites |
| `/form/*` (`generate.js`, `submit`, `embed/{id}`, `message`, `company-lookup/autocomplete`) | Public forms |
| `/email/*` (view, unsubscribe incl. RFC 8058 one-click `POST`, `dnc`, `resubscribe`, open pixel) | Links and pixels in sent emails |
| `/r/*`, `/redirect/*`, `/asset/*` | Tracked links and public assets |
| `/mailer/callback`, `/sms/{transport}/callback`, `/sms/receive`, `/notification/*` | ESP bounce/complaint webhooks, SMS callbacks, push subscriptions |
| `/plugin/{integration}/tracking.gif`, `/social/generate/{formName}.js`, `/integration/{integration}/callback` | Plugin tracking, social-login forms, integration OAuth callbacks |
| `/media/*`, `/themes/*/assets/*`, `/app/assets/*`, `/favicon.ico`, `/robots.txt` | Static assets |

**Residual.** If Traefik and Mautic ever disagree about whether a path is the admin UI (an
encoding or normalisation Traefik does not resolve to `/s/`), that request would reach Mautic
without `mpass-auth`, and a surviving Mautic session cookie alone would serve it. Go-side decoding
of `%XX` and Symfony's single `rawurldecode` agree on every case we know of. Setting
`MPASS_EDGE_SECRET` closes this regardless: an admin-UI request that did not come through
`mautic-secure` has no secret and gets `403`.

## Operations

**Image.** Mautic ships no Dockerfile (the official image is the separate `mautic/docker-mautic`),
so this fork owns `Dockerfile` and `docker/mpass/entrypoint.sh`. Code, vendor and compiled assets
are baked; never mount source. Build for the bundle's hosts:

```bash
docker buildx build --platform linux/amd64 -t <registry>/mautic:<tag> --push .
```

**What the entrypoint does at boot** (don't duplicate it in provisioning):

1. Under SSO, refuse an unsafe configuration: a `config/security_local.php` (it would replace the
   SSO firewall), a set but short `MPASS_EDGE_SECRET`, or no `SMB_CORPORATE_ID` without
   `MPASS_ALLOW_ANY_TENANT=1`. Also refuse a non-positive session TTL.
2. `mautic:install` from the CLI on first start only (DB credentials and a placeholder admin are
   seeded into `config/local.php`, then the admin keys are removed).
3. Render `config/parameters_local.php`: `site_url`, `trusted_proxies`, `trusted_hosts`.
4. Render the php.ini session settings from `SESSION_COOKIE_MAX_AGE_SECONDS`.
5. `cache:warmup --env=prod` (after `site_url` exists, so the session cookie is `secure`).
6. Under SSO, create the `mPass Member` role (marketer permissions) if missing.
7. Start Apache; the edge secret, if set, is moved into `/run/mpass/edge-secret`.

**Processes.** One image:

| Process | Command | Notes |
|---|---|---|
| web | default (`apache2-foreground`) | Port 80 on the backend/frontend networks; never published |
| cron | `mautic-entrypoint php bin/console <command>` | Same image, volumes and **SSO environment** as web (so the outbound guard is on for cron-fired webhooks). Runs as www-data; needs the web container to have installed first. Typical: `mautic:segments:update`, `mautic:campaigns:update`, `mautic:campaigns:trigger`, `mautic:messages:send`, `mautic:emails:send`, `mautic:broadcasts:send`, `mautic:import`, `mautic:webhooks:process` |

**Health check:** built into the image (`GET http://127.0.0.1/robots.txt` from inside the
container). From the edge, `/robots.txt` is on the public router.

**Database:** MariaDB 10.11 (or MySQL 8). **Volumes:** `/var/www/html/config` (holds `local.php`
with the generated `secret_key`), `/var/www/html/media/files`, `/var/www/html/media/images`.

**Admins.** Nobody has a password; grant admin from a shell (works before the person's first
login):

```bash
docker compose exec -u www-data mautic php /opt/mautic-users.php grant-admin <email>...
docker compose exec -u www-data mautic php /opt/mautic-users.php revoke-admin <email>...
docker compose exec -u www-data mautic php /opt/mautic-users.php list
docker compose exec -u www-data mautic php /opt/mautic-users.php member-perms <marketer|contributor|viewer|none>
```

**Local testing:** `docker/mpass/docker-compose.devkit.yml`, an extra compose file for the
mpass-sso-devkit (see its header). **Smoke test:** [`docs/mautic-smoke-test.md`](../docs/mautic-smoke-test.md).

## Tests

- `app/bundles/UserBundle/Tests/Functional/Mpass/`: PHPUnit functional tests through the real
  kernel (authenticator, guard, edge secret, outbound guard).
- `app/bundles/CoreBundle/Tests/js/mpassReload.test.mjs`: the tab-reload handler (`node --test`).
- `docker/mpass/tests/image-test.sh`: the built image (entrypoint refusals, file ownership, session
  TTL, edge-secret handling, role bootstrap).
