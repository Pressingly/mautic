#!/bin/sh
# Mautic entrypoint for the FOSS bundle (mPass SSO). Order matters (sso-rules-moneta
# apps/mautic/security.md G4, G12, G13c):
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
#   SESSION_TTL_SECONDS       Layer-2 session TTL (default 28800)
# SSO settings read by the app at runtime, never written to any Mautic config file:
#   AUTH_TYPE=SSO, DEFAULT_EMAIL_DOMAIN, SMB_CORPORATE_ID, MPASS_SSO_DEFAULT_ROLE (role id),
#   MPASS_PORTAL_URL
#
# Persist /var/www/html/config (local.php holds the generated secret_key), media/files and
# media/images as volumes. Never mount source into this container.
set -eu
cd /var/www/html

: "${MAUTIC_SITE_URL:?MAUTIC_SITE_URL is required}"

# app/config/config_prod.php loads config/security_local.php INSTEAD of app/config/security.php when
# it exists, which would drop the mPass authenticator from the main firewall.
if [ "${AUTH_TYPE:-}" = "SSO" ] && [ -e config/security_local.php ]; then
    echo "config/security_local.php replaces the SSO firewall; refusing to start" >&2
    exit 1
fi
console() { su -s /bin/sh www-data -c "php bin/console $*"; }

# config/ may be an empty volume on first start.
mkdir -p config var/cache var/logs media/files media/images
chown -R www-data:www-data config var media/files media/images

# 1. Install (CLI only; /installer* is 404 under SSO and gated at the edge).
if ! grep -qs "site_url" config/local.php; then
    : "${MAUTIC_ADMIN_EMAIL:?MAUTIC_ADMIN_EMAIL is required for the first start}"
    admin_password=$(php -r 'echo bin2hex(random_bytes(24));')
    su -s /bin/sh www-data -c 'php bin/console mautic:install "$0" --no-interaction --force \
        --db_driver=pdo_mysql --db_host="$1" --db_port="$2" --db_name="$3" --db_user="$4" --db_password="$5" \
        --admin_email="$6" --admin_username="$6" --admin_firstname="${6%%@*}" --admin_lastname="${6#*@}" \
        --admin_password="$7"' \
        "$MAUTIC_SITE_URL" "${MAUTIC_DB_HOST:?}" "${MAUTIC_DB_PORT:-3306}" "${MAUTIC_DB_NAME:?}" \
        "${MAUTIC_DB_USER:?}" "${MAUTIC_DB_PASSWORD:?}" "$MAUTIC_ADMIN_EMAIL" "$admin_password"
    unset admin_password
fi
grep -qs "site_url" config/local.php && grep -qs "db_driver" config/local.php \
    || { echo "config/local.php lacks site_url/db_driver: /installer would stay reachable" >&2; exit 1; }

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
ttl="${SESSION_TTL_SECONDS:-28800}"
case "$ttl" in ''|*[!0-9]*) echo "SESSION_TTL_SECONDS must be an integer" >&2; exit 1 ;; esac
cat > /usr/local/etc/php/conf.d/zz-mpass-session.ini <<EOF
session.gc_maxlifetime = $ttl
session.cookie_lifetime = $ttl
session.gc_probability = 1
session.gc_divisor = 100
EOF

# 4. Compile the container now that site_url exists (a stale one would bake cookie_secure=false).
rm -rf var/cache/prod
console cache:warmup --env=prod --no-debug

# 5.
exec "$@"
