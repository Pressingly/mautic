#!/bin/sh
# Mautic entrypoint for the FOSS bundle (mPass SSO). Order matters (sso-rules-moneta
# apps/mautic/security.md G4, G12, G13c):
#   0. refuse an unsafe SSO configuration;
#   1. mautic:install — a no-op once config/local.php has db_driver and site_url;
#   2. render config/parameters_local.php — AFTER step 1: the kernel counts the app as installed as
#      soon as site_url is in its local config, so rendering it first would skip the install;
#   3. render the php.ini session drop-in from SESSION_COOKIE_MAX_AGE_SECONDS;
#   4. cache:warmup --env=prod — AFTER step 2: config.php reads site_url at compile time;
#   5. under SSO, create the "mPass Member" default role if missing (idempotent);
#   6. start Apache.
#
# Deployment env (MAUTIC_* names match Mautic's own config keys):
#   MAUTIC_SITE_URL           required, e.g. https://mautic.${SMB_NAME}.${PLATFORM_DOMAIN}
#   MAUTIC_DB_HOST, MAUTIC_DB_PORT (3306), MAUTIC_DB_NAME, MAUTIC_DB_USER, MAUTIC_DB_PASSWORD
#   (No admin email: mautic:install needs an admin row, so it gets a placeholder,
#   mautic-install@admin.invalid, with a random discarded password. .invalid is reserved, so no
#   mPass identity can ever match it. Real admins are granted with /opt/mautic-users.php grant-admin.)
#   TRUSTED_PROXIES           comma-separated, e.g. the Traefik network CIDR (required behind Traefik)
#   TRUSTED_HOSTS             comma-separated regexes; default: the site_url host
#   (Not MAUTIC_TRUSTED_*: ConfigEnvVars maps every Mautic config key K to an env override
#   MAUTIC_<K>, and Mautic would parse those as JSON while TrustMiddleware ignores them.)
#   SESSION_COOKIE_MAX_AGE_SECONDS  Layer-2 session TTL, > 0 (default 432000, the platform's)
# SSO settings read by the app at runtime, never written to any Mautic config file:
#   AUTH_TYPE=SSO, DEFAULT_EMAIL_DOMAIN, SMB_CORPORATE_ID (or MPASS_ALLOW_ANY_TENANT=1),
#   LOGOUT_REDIRECT_URL, MPASS_SSO_DEFAULT_ROLE (optional role id; default the "mPass Member" role),
#   MPASS_EDGE_SECRET (required, >= 32 chars; the protected Traefik router injects it. Unset, short or
#   a CHANGE_ME_ placeholder: identity headers are never trusted, so nobody can sign in, logged at startup),
#   MPASS_COGNITO_ISSUER_URL (or COGNITO_AWS_REGION + COGNITO_USER_POOL_ID), MPASS_TOKEN_ISSUER_URL
#   (optional), MPASS_OIDC_CLIENT_ID: verify the forwarded token when SMB_CORPORATE_ID is set
# Full list: doc/mpass_sso.md.
#
# Persist /var/www/html/config (local.php holds the generated secret_key), media/files and
# media/images as volumes. Never mount source into this container.
set -eu
cd /var/www/html

fail() { echo "mautic-entrypoint: $*" >&2; exit 1; }
warn() { echo "mautic-entrypoint: ERROR: $*" >&2; }
trim() { printf '%s' "${1:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
# A setting's value, or empty when unset or still an .env.example CHANGE_ME_ placeholder.
configured() { value="$(trim "${1:-}")"; case "$value" in CHANGE_ME_*) ;; *) printf '%s' "$value" ;; esac; }
# Mirrors MpassTokenVerifier::isConfigured(): a client id and at least one trusted issuer.
# The edge secret from MPASS_EDGE_SECRET, else from a mounted MPASS_EDGE_SECRET_FILE, read here as
# root. Apache gets it only through the copy in /run/mpass/edge-secret, so a file www-data cannot
# read (a root-owned 0400 Kubernetes secret) still works.
edge_secret_value() {
    value="$(configured "${MPASS_EDGE_SECRET:-}")"
    if [ -z "$value" ] && [ -n "${MPASS_EDGE_SECRET_FILE:-}" ] && [ -r "$MPASS_EDGE_SECRET_FILE" ]; then
        value="$(configured "$(cat "$MPASS_EDGE_SECRET_FILE")")"
    fi
    printf '%s' "$value"
}
token_verifier_configured() {
    [ -n "$(configured "${MPASS_OIDC_CLIENT_ID:-}")" ] || return 1
    [ -n "$(configured "${MPASS_COGNITO_ISSUER_URL:-}")" ] && return 0
    [ -n "$(configured "${MPASS_TOKEN_ISSUER_URL:-}")" ] && return 0
    [ -n "$(configured "${COGNITO_AWS_REGION:-}")" ] && [ -n "$(configured "${COGNITO_USER_POOL_ID:-}")" ]
}

: "${MAUTIC_SITE_URL:?MAUTIC_SITE_URL is required}"

# 0. Unsafe SSO configurations.
if [ "${AUTH_TYPE:-}" = "SSO" ]; then
    # app/config/config_prod.php loads config/security_local.php INSTEAD of app/config/security.php
    # when it exists, which would drop the mPass authenticator from the main firewall.
    [ -e config/security_local.php ] && fail "config/security_local.php replaces the SSO firewall; refusing to start"
    # Without a usable secret the app trusts no identity header (fail closed): mPass sign-in is
    # off, but landing pages, forms, tracking, the API and cron keep working, so this is logged
    # rather than fatal. Under 32 characters it is guessable by anything on the bundle networks.
    edge_secret="$(edge_secret_value)"
    if [ "${#edge_secret}" -lt 32 ]; then
        warn "MPASS_EDGE_SECRET is unset, a CHANGE_ME_ placeholder or shorter than 32 characters: mPass identity headers are ignored and nobody can sign in"
    fi
    if [ -n "$(configured "${SMB_CORPORATE_ID:-}")" ] && ! token_verifier_configured; then
        warn "SMB_CORPORATE_ID is set but no token issuer or client id is configured (MPASS_COGNITO_ISSUER_URL, MPASS_OIDC_CLIENT_ID): every mPass login will be refused"
    fi
    # Without a corporate binding every principal in the Cognito pool gets a seat. Allowed only
    # when the deployment says so explicitly.
    if [ -z "$(configured "${SMB_CORPORATE_ID:-}")" ] && [ "${MPASS_ALLOW_ANY_TENANT:-}" != "1" ]; then
        fail "AUTH_TYPE=SSO needs SMB_CORPORATE_ID, or MPASS_ALLOW_ANY_TENANT=1 to admit the whole pool"
    fi
fi

ttl="${SESSION_COOKIE_MAX_AGE_SECONDS:-432000}"
case "$ttl" in ''|*[!0-9]*) fail "SESSION_COOKIE_MAX_AGE_SECONDS must be a positive integer" ;; esac
[ "$ttl" -gt 0 ] || fail "SESSION_COOKIE_MAX_AGE_SECONDS must be a positive integer (0 would mean no expiry)"

# Command mode, for cron/worker containers: `mautic-entrypoint php bin/console mautic:campaigns:trigger`.
# Same image, same volumes and the SAME SSO environment as the web container (AUTH_TYPE,
# MPASS_EDGE_SECRET, the token issuer settings, SMB_CORPORATE_ID or MPASS_ALLOW_ANY_TENANT, ...), so the checks above ran and
# e.g. the outbound guard is on for campaign webhooks fired by cron. No install, no warm-up: the web
# container owns those; the command runs as www-data against the installed config/.
if [ "$#" -gt 0 ] && [ "$1" != "apache2-foreground" ]; then
    grep -qs "site_url" config/local.php || fail "not installed yet: start the web container first"
    # setpriv, not su: su would parse the command's own options (php -r ...) as its own.
    exec setpriv --reuid=www-data --regid=www-data --init-groups -- "$@"
fi

console() { su -s /bin/sh www-data -c "php bin/console $*"; }

# Removes the admin_* keys seeded for the install (the throwaway admin password among them).
strip_admin_keys() {
    [ -f config/local.php ] || return 0
    su -s /bin/sh www-data -c 'php -r '"'"'
$file = "config/local.php";
include $file;
foreach (array_keys($parameters) as $key) {
    if (str_starts_with($key, "admin_")) { unset($parameters[$key]); }
}
file_put_contents($file, "<?php\n\$parameters = ".var_export($parameters, true).";\n");
chmod($file, 0600);
'"'"''
}

# config/ may be an empty volume on first start.
mkdir -p config var/cache var/logs media/files media/images
chown -R www-data:www-data config var media/files media/images

# 1. Install (CLI only; /installer* is 404 under SSO and gated at the edge). The DB credentials and
#    the admin are seeded into config/local.php, which mautic:install reads when an option is not
#    given (InstallCommand.php:199-208), so no secret appears on a command line (/proc/*/cmdline).
#    The seeded admin_* keys are removed again afterwards.
if ! grep -qs "site_url" config/local.php; then
    : "${MAUTIC_DB_HOST:?}" "${MAUTIC_DB_NAME:?}" "${MAUTIC_DB_USER:?}" "${MAUTIC_DB_PASSWORD:?}"
    su -s /bin/sh www-data -c 'php -r '"'"'
$file = "config/local.php";
$parameters = [];
if (is_file($file)) { include $file; }
$email = "mautic-install@admin.invalid";
$parameters = array_merge($parameters, [
    "db_driver"       => "pdo_mysql",
    "db_host"         => (string) getenv("MAUTIC_DB_HOST"),
    "db_port"         => (string) (getenv("MAUTIC_DB_PORT") ?: "3306"),
    "db_name"         => (string) getenv("MAUTIC_DB_NAME"),
    "db_user"         => (string) getenv("MAUTIC_DB_USER"),
    "db_password"     => (string) getenv("MAUTIC_DB_PASSWORD"),
    "admin_email"     => $email,
    "admin_username"  => $email,
    "admin_firstname" => "Install",
    "admin_lastname"  => "Placeholder",
    "admin_password"  => bin2hex(random_bytes(24)),
]);
file_put_contents($file, "<?php\n\$parameters = ".var_export($parameters, true).";\n");
chmod($file, 0600);
'"'"''
    # The seeded db_driver alone does not count as installed (InstallService::checkIfInstalled needs
    # site_url too), so the install runs. The URL reaches the command through the environment, never
    # through string interpolation into a shell command.
    if ! su -s /bin/sh www-data -c 'php bin/console mautic:install "$MAUTIC_SITE_URL" --no-interaction --force'; then
        strip_admin_keys
        fail "mautic:install failed (the seeded admin keys were removed again)"
    fi
    strip_admin_keys
fi
grep -qs "site_url" config/local.php && grep -qs "db_driver" config/local.php \
    || fail "config/local.php lacks site_url/db_driver: /installer would stay reachable"

# 2. parameters_local.php: the one source every reader honours (config.php, the kernel's installed
#    check, TrustMiddleware). Values are var_export()ed, never interpolated into PHP source.
#    api_enabled is deliberately not here: it overrides config/local.php, so writing it would undo
#    the admin's Configuration setting on every boot. The API stays an admin setting (default off).
su -s /bin/sh www-data -c 'php -r '"'"'
$list = static fn (string $v): array => array_values(array_filter(array_map("trim", explode(",", $v))));
$host = (string) parse_url((string) getenv("MAUTIC_SITE_URL"), PHP_URL_HOST);
$parameters = [
    "site_url"        => (string) getenv("MAUTIC_SITE_URL"),
    "trusted_proxies" => $list((string) getenv("TRUSTED_PROXIES")),
    "trusted_hosts"   => $list((string) getenv("TRUSTED_HOSTS")) ?: ["^".preg_quote($host)."\$"],
];
file_put_contents("config/parameters_local.php", "<?php\n\$parameters = ".var_export($parameters, true).";\n");
'"'"''

# 3. Session TTL from SESSION_COOKIE_MAX_AGE_SECONDS, the name the bundle sets on every app.
cat > /usr/local/etc/php/conf.d/zz-mpass-session.ini <<EOF
session.gc_maxlifetime = $ttl
session.cookie_lifetime = $ttl
session.gc_probability = 1
session.gc_divisor = 100
EOF

# 4. Compile the container now that site_url exists (a stale one would bake cookie_secure=false).
rm -rf var/cache/prod
console cache:warmup --env=prod --no-debug

# 5. The SSO default role, so first logins work without copying a role id into env. Idempotent:
#    an existing "mPass Member" role (and permissions an admin changed) is left as is.
if [ "${AUTH_TYPE:-}" = "SSO" ]; then
    su -s /bin/sh www-data -c 'php /opt/mautic-users.php ensure-member-role'
fi

# 6. Apache's canonical scheme://host for its own redirects (apache-vhost.conf).
MAUTIC_SERVER_NAME=$(php -r '$u = parse_url((string) getenv("MAUTIC_SITE_URL")); echo ($u["scheme"] ?? "https")."://".($u["host"] ?? "localhost").(isset($u["port"]) ? ":".$u["port"] : "");')
export MAUTIC_SERVER_NAME

# The edge secret reaches Apache as a file, not as an environment variable: under mod_php the
# Apache environment is visible to phpinfo() and any environment dump. Root-owned, readable by
# www-data only; ProxyIdentity reads MPASS_EDGE_SECRET_FILE.
edge_secret="$(edge_secret_value)"
if [ -n "$edge_secret" ]; then
    mkdir -p /run/mpass
    umask 077
    printf '%s' "$edge_secret" > /run/mpass/edge-secret
    chown root:www-data /run/mpass /run/mpass/edge-secret
    chmod 0750 /run/mpass
    chmod 0440 /run/mpass/edge-secret
    export MPASS_EDGE_SECRET_FILE=/run/mpass/edge-secret
fi
unset MPASS_EDGE_SECRET edge_secret
exec "$@"
