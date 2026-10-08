# Mautic smoke test (mPass SSO)

> **Draft.** Built from the mpass-sso-devkit README "Test your app" list and the
> sso-rules-moneta devkit e2e checks. Replace the table with the onboarding guide §8.4 table
> once it is available.

Run after every deploy, and after any change to the SSO code. `HOST` is Mautic's host,
`PORTAL` the platform portal. Use a private window, and keep `https://whoami.<platform domain>`
open to see the raw headers the edge sends.

Setup: `AUTH_TYPE=SSO`, `DEFAULT_EMAIL_DOMAIN` set, `LOGOUT_REDIRECT_URL=https://PORTAL`,
`SMB_CORPORATE_ID` or `MPASS_ALLOW_ANY_TENANT=1`. In the examples, `users` is
`docker compose exec -u www-data mautic php /opt/mautic-users.php`.

## With a browser

| # | Step | Pass |
|---|---|---|
| 1 | Open `https://HOST/s/dashboard` | QR page; after scanning, the dashboard as your mPass identity. No password form, no installer |
| 2 | `users list` | One row for you, role `mPass Member`, not admin. Name: the part of your email before `@` as first name, `-` as last name |
| 3 | Open `https://HOST/s/dashboard` again in a new tab | Dashboard, no login page |
| 4 | Account settings, and Users > edit yourself as an admin | No password fields; email and username can't be changed |
| 4b | Change your first and last name in Account settings, "Log out of all apps", log in again | The edited names are kept |
| 5 | Logout in the user menu | Lands on `https://PORTAL`. Opening `HOST/s/dashboard` again logs you straight back in |
| 6 | Portal "Log out of all apps", then reload an open Mautic tab and wait for the keep-alive | The tab goes to the QR page |
| 7 | Log in as A, "Log out of all apps", log in as B, reload the open Mautic tab | Served as B, never A |
| 8 | `users grant-admin <your email>`, reload | Admin menu appears. `users revoke-admin <your email>` takes it away |
| 9 | Publish a landing page and a form; open the page and submit the form in a window with no mPass session. Then embed the form "via iframe" (`<iframe src="https://HOST/form/<id>">`) in a local HTML page and submit it there | Both work without a login, including inside the iframe |

## With curl

| # | Request | Pass |
|---|---|---|
| 10 | `curl -skI https://HOST/s/dashboard` (no cookie) | `302` to the mPass login |
| 11 | `curl -skI -H 'X-Auth-Request-Email: someone-else@example.com' https://HOST/s/dashboard` | `302` to the mPass login, not a session |
| 12 | With the `_oauth2_proxy` cookie and a spoofed `X-Auth-Request-Email`, against `https://whoami.<domain>/` | Your own identity, not the spoofed one |
| 13 | Without a cookie: `/robots.txt`, `/mtc.js`, `/mtracking.gif`, `/form/generate.js?id=1`, `/<landing page slug>`, `/dwc/<alias>`, `/focus/1.js`, `/email/view/<hash>` | Reach Mautic (no redirect to mPass) |
| 14 | Without a cookie: `/s/login`, `/s/users`, `/index.php/s/dashboard`, `/installer`, `/elfinder` | `302` to the mPass login |
| 15 | With the `_oauth2_proxy` cookie: `POST /passwordreset`, `GET /invite/x`, `GET /s/saml/login`, `GET /oauth/v2/authorize_login`, `POST /api/users/new`, `GET /installer` | `404` for every one |
| 16a | Without a cookie, through the edge: `POST https://HOST/oauth/v2/token` and `GET https://HOST/api/contacts` | `302` to the mPass login for both (the API is internal-only) |
| 16b | As an admin: enable the API in Configuration and create an OAuth 2 client in Settings > API Credentials. Then run the [16b command](#16b-internal-api-call) from inside the network | `200`, no mPass session involved |
| 17 | With the `_oauth2_proxy` cookie: `GET /s/dashboard` with `Authorization: Bearer x` | `401` |
| 18 | `curl -skI https://HOST/s/dashboard` with the cookie; then, without one, `curl -skI https://HOST/form/embed/<id>` and a landing page | Admin UI: `Strict-Transport-Security`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` present. Form and landing page: the same, but no `X-Frame-Options` (they are framed on customer sites) |

### 16b: internal API call

Run from the devkit directory, with `<site host>` the host of `MAUTIC_SITE_URL` and the client's
public id and secret. Both headers are required: without `Host` Mautic answers `400 Untrusted Host`
(only the site host is trusted), and without `X-Forwarded-Proto: https` the token request is `404`
(the OAuth2 routes are https-only).

```bash
docker compose exec mautic sh -c '
H="-H Host:<site host> -H X-Forwarded-Proto:https"
T=$(curl -s $H -X POST http://mautic/oauth/v2/token -d grant_type=client_credentials \
      -d client_id=<public id> -d client_secret=<secret> | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
curl -s -o /dev/null -w "%{http_code}\n" $H -H "Authorization: Bearer $T" http://mautic/api/contacts'
```

## Configuration failures

| # | Change, then `docker compose up -d` the Mautic service | Pass |
|---|---|---|
| 19 | Set `DEFAULT_EMAIL_DOMAIN` to empty (`DEFAULT_EMAIL_DOMAIN=` in the devkit's `.env`; the devkit sends a bare mPass id) | Login refused with the mPass refusal page (`unresolvable`); no user created |
| 20 | Set `SMB_CORPORATE_ID` to a value your account doesn't have (on the app only) | `403` refusal page (`corporate`), no user created; an open session is flushed |
| 21 | Unset both `SMB_CORPORATE_ID` and `MPASS_ALLOW_ANY_TENANT` | The container refuses to start and names both variables |
| 22 | Set `MPASS_EDGE_SECRET=short` | The container refuses to start |
| 23 | Set `LOGOUT_REDIRECT_URL=not-a-url`, then Logout | A static page, no redirect; an error in the Mautic log |

Put every setting back afterwards.
