#!/bin/sh
# Mautic entrypoint for the FOSS bundle (mPass SSO). Order matters (sso-rules-moneta
# apps/mautic/security.md G4, G12, G13c):
#   0. refuse an unsafe SSO configuration;
#   1. mautic:install — a no-op once config/local.php has db_driver and site_url;
#   2. render config/parameters_local.php — AFTER step 1: the kernel counts the app as installed as
#      soon as site_url is in its local config, so rendering it first would skip the install;
#   3. render the php.ini session drop-in from SESSION_TTL_SECONDS;
#   4. cache:warmup --env=prod — AFTER step 2: config.php reads site_url at compile time;
#   5. start Apache.
#
# Deployment env (MAUTIC_* names match Mautic's own config keys):
#   MAUTIC_SITE_URL           required, e.g. https://mautic.${SMB_NAME}.${PLATFORM_DOMAIN}
#   MAUTIC_DB_HOST, MAUTIC_DB_PORT (3306), MAUTIC_DB_NAME, MAUTIC_DB_USER, MAUTIC_DB_PASSWORD
#   MAUTIC_ADMIN_EMAIL        required on first start only: the operator's mPass email. The admin's
#                             password is random and discarded; the operator signs in through mPass.
#   TRUSTED_PROXIES           comma-separated, e.g. the Traefik network CIDR (required behind Traefik)
#   TRUSTED_HOSTS             comma-separated regexes; default: the site_url host
#   (Not MAUTIC_TRUSTED_*: ConfigEnvVars maps every Mautic config key K to an env override
#   MAUTIC_<K>, and Mautic would parse those as JSON while TrustMiddleware ignores them.)
#   SESSION_TTL_SECONDS       Layer-2 session TTL, > 0 (default 28800)
# SSO settings read by the app at runtime, never written to any Mautic config file:
#   AUTH_TYPE=SSO, MPASS_EDGE_SECRET (>= 32 chars; the protected Traefik router injects it),
#   DEFAULT_EMAIL_DOMAIN, SMB_CORPORATE_ID (or MPASS_ALLOW_ANY_TENANT=1), MPASS_SSO_DEFAULT_ROLE
#   (role id), MPASS_PORTAL_URL
#
# Persist /var/www/html/config (local.php holds the generated secret_key), media/files and
# media/images as volumes. Never mount source into this container.
set -eu
cd /var/www/html

fail() { echo "mautic-entrypoint: $*" >&2; exit 1; }

: "${MAUTIC_SITE_URL:?MAUTIC_SITE_URL is required}"

# 0. Unsafe SSO configurations.
if [ "${AUTH_TYPE:-}" = "SSO" ]; then
    # app/config/config_prod.php loads config/security_local.php INSTEAD of app/config/security.php
    # when it exists, which would drop the mPass authenticator from the main firewall.
    [ -e config/security_local.php ] && fail "config/security_local.php replaces the SSO firewall; refusing to start"
    # Without it, ProxyIdentity trusts no identity header at all (every login would fail), and a
    # short one is guessable by anything on the bundle networks.
    edge_secret="${MPASS_EDGE_SECRET:-}"
    [ "${#edge_secret}" -ge 32 ] || fail "AUTH_TYPE=SSO needs MPASS_EDGE_SECRET (>= 32 chars), the value the protected router injects"
    # Without a corporate binding every principal in the Cognito pool gets a seat. Allowed only
    # when the deployment says so explicitly.
    if [ -z "${SMB_CORPORATE_ID:-}" ] && [ "${MPASS_ALLOW_ANY_TENANT:-}" != "1" ]; then
        fail "AUTH_TYPE=SSO needs SMB_CORPORATE_ID, or MPASS_ALLOW_ANY_TENANT=1 to admit the whole pool"
    fi
fi

ttl="${SESSION_TTL_SECONDS:-28800}"
case "$ttl" in ''|*[!0-9]*) fail "SESSION_TTL_SECONDS must be a positive integer" ;; esac
[ "$ttl" -gt 0 ] || fail "SESSION_TTL_SECONDS must be a positive integer (0 would mean no expiry)"

# Command mode, for cron/worker containers: `mautic-entrypoint php bin/console mautic:campaigns:trigger`.
# Same image, same volumes and the SAME SSO environment as the web container (AUTH_TYPE,
# MPASS_EDGE_SECRET, SMB_CORPORATE_ID or MPASS_ALLOW_ANY_TENANT, ...), so the checks above ran and
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
    : "${MAUTIC_ADMIN_EMAIL:?MAUTIC_ADMIN_EMAIL is required for the first start}"
    : "${MAUTIC_DB_HOST:?}" "${MAUTIC_DB_NAME:?}" "${MAUTIC_DB_USER:?}" "${MAUTIC_DB_PASSWORD:?}"
    su -s /bin/sh www-data -c 'php -r '"'"'
$file = "config/local.php";
$parameters = [];
if (is_file($file)) { include $file; }
$email = strtolower(trim((string) getenv("MAUTIC_ADMIN_EMAIL")));
[$local, $domain] = array_pad(explode("@", $email, 2), 2, "mpass");
$parameters = array_merge($parameters, [
    "db_driver"       => "pdo_mysql",
    "db_host"         => (string) getenv("MAUTIC_DB_HOST"),
    "db_port"         => (string) (getenv("MAUTIC_DB_PORT") ?: "3306"),
    "db_name"         => (string) getenv("MAUTIC_DB_NAME"),
    "db_user"         => (string) getenv("MAUTIC_DB_USER"),
    "db_password"     => (string) getenv("MAUTIC_DB_PASSWORD"),
    "admin_email"     => $email,
    "admin_username"  => $email,
    "admin_firstname" => $local,
    "admin_lastname"  => $domain,
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
su -s /bin/sh www-data -c 'php -r '"'"'
$list = static fn (string $v): array => array_values(array_filter(array_map("trim", explode(",", $v))));
$host = (string) parse_url((string) getenv("MAUTIC_SITE_URL"), PHP_URL_HOST);
$parameters = [
    "site_url"        => (string) getenv("MAUTIC_SITE_URL"),
    "trusted_proxies" => $list((string) getenv("TRUSTED_PROXIES")),
    "trusted_hosts"   => $list((string) getenv("TRUSTED_HOSTS")) ?: ["^".preg_quote($host)."\$"],
    "api_enabled"     => false,
];
file_put_contents("config/parameters_local.php", "<?php\n\$parameters = ".var_export($parameters, true).";\n");
'"'"''

# 3. Session TTL adapter (session-lifecycle: SESSION_TTL_SECONDS is the one operator-facing name).
cat > /usr/local/etc/php/conf.d/zz-mpass-session.ini <<EOF
session.gc_maxlifetime = $ttl
session.cookie_lifetime = $ttl
session.gc_probability = 1
session.gc_divisor = 100
EOF

# 4. Compile the container now that site_url exists (a stale one would bake cookie_secure=false).
rm -rf var/cache/prod
console cache:warmup --env=prod --no-debug

# 5. Apache's canonical scheme://host for its own redirects (apache-vhost.conf).
MAUTIC_SERVER_NAME=$(php -r '$u = parse_url((string) getenv("MAUTIC_SITE_URL")); echo ($u["scheme"] ?? "https")."://".($u["host"] ?? "localhost").(isset($u["port"]) ? ":".$u["port"] : "");')
export MAUTIC_SERVER_NAME

# The edge secret reaches Apache as a file, not as an environment variable: under mod_php the
# Apache environment is visible to phpinfo() and any environment dump. Root-owned, readable by
# www-data only; ProxyIdentity reads MPASS_EDGE_SECRET_FILE.
if [ -n "${MPASS_EDGE_SECRET:-}" ]; then
    mkdir -p /run/mpass
    umask 077
    printf '%s' "$MPASS_EDGE_SECRET" > /run/mpass/edge-secret
    chown root:www-data /run/mpass /run/mpass/edge-secret
    chmod 0750 /run/mpass
    chmod 0440 /run/mpass/edge-secret
    export MPASS_EDGE_SECRET_FILE=/run/mpass/edge-secret
    unset MPASS_EDGE_SECRET
fi
exec "$@"
