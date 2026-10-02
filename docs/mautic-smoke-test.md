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
| 2 | `users list` | One row for you, role `mPass Member`, not admin. Name: local part + domain |
| 3 | Open `https://HOST/s/dashboard` again in a new tab | Dashboard, no login page |
| 4 | Account settings, and Users > edit yourself as an admin | No password fields; email and username can't be changed |
| 5 | Logout in the user menu | Lands on `https://PORTAL`. Opening `HOST/s/dashboard` again logs you straight back in |
| 6 | Portal "Log out of all apps", then reload an open Mautic tab and wait for the keep-alive | The tab goes to the QR page |
| 7 | Log in as A, "Log out of all apps", log in as B, reload the open Mautic tab | Served as B, never A |
| 8 | `users grant-admin <your email>`, reload | Admin menu appears. `users revoke-admin <your email>` takes it away |
| 9 | Publish a landing page and a form; open the page and submit the form in a window with no mPass session | Both work without a login |

## With curl

| # | Request | Pass |
|---|---|---|
| 10 | `curl -skI https://HOST/s/dashboard` (no cookie) | `302` to the mPass login |
| 11 | `curl -skI -H 'X-Auth-Request-Email: someone-else@example.com' https://HOST/s/dashboard` | `302` to the mPass login, not a session |
| 12 | With the `_oauth2_proxy` cookie and a spoofed `X-Auth-Request-Email`, against `https://whoami.<domain>/` | Your own identity, not the spoofed one |
| 13 | Without a cookie: `/robots.txt`, `/mtc.js`, `/mtracking.gif`, `/form/generate.js?id=1`, `/<landing page slug>`, `/dwc/<alias>`, `/focus/1.js`, `/email/view/<hash>` | Reach Mautic (no redirect to mPass) |
| 14 | Without a cookie: `/s/login`, `/s/users`, `/index.php/s/dashboard`, `/installer`, `/elfinder` | `302` to the mPass login |
| 15 | With the `_oauth2_proxy` cookie: `POST /passwordreset`, `GET /invite/x`, `GET /s/saml/login`, `GET /oauth/v2/authorize_login`, `POST /api/users/new`, `GET /installer` | `404` for every one |
| 16 | API enabled in Configuration, an API client with client credentials: `POST /oauth/v2/token` (`grant_type=client_credentials`), then `GET /api/contacts` with the token | Token issued, contacts returned, no mPass session involved |
| 17 | With the `_oauth2_proxy` cookie: `GET /s/dashboard` with `Authorization: Bearer x` | `401` |
| 18 | `curl -skI https://HOST/s/dashboard` with the cookie | `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` present |

## Configuration failures

| # | Change, then `docker compose up -d` the Mautic service | Pass |
|---|---|---|
| 19 | Unset `DEFAULT_EMAIL_DOMAIN` (the devkit sends a bare mPass id) | Login refused with the mPass refusal page (`unresolvable`); no user created |
| 20 | Set `SMB_CORPORATE_ID` to a value your account doesn't have (on the app only) | `403` refusal page (`corporate`), no user created; an open session is flushed |
| 21 | Unset both `SMB_CORPORATE_ID` and `MPASS_ALLOW_ANY_TENANT` | The container refuses to start and names both variables |
| 22 | Set `MPASS_EDGE_SECRET=short` | The container refuses to start |
| 23 | Set `LOGOUT_REDIRECT_URL=not-a-url`, then Logout | A static page, no redirect; an error in the Mautic log |

Put every setting back afterwards.
