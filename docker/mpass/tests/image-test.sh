 #!/usr/bin/env bash
# Image-level tests for the mPass SSO build (sso-rules-moneta tasks 5.23, 5.26, 5.29, plus the
# entrypoint's refusals). They need a real container, so they are not PHPUnit tests.
#
# Usage: docker/mpass/tests/image-test.sh <image> <docker-network> <db-host> <db-user> <db-password> <db-name>
#   The database must exist and be empty; the script installs into it. The network must reach it.
#   Probes run from a throwaway container on the same network (curlimages/curl).
set -uo pipefail

IMAGE=$1 NET=$2 DB_HOST=$3 DB_USER=$4 DB_PASS=$5 DB_NAME=$6
NAME=mautic-image-test-$$
SECRET=$(openssl rand -hex 24)
SITE=https://mautic.image-test.example
HOST=mautic.image-test.example
failures=0

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
curl_in() { docker run --rm --network "$NET" curlimages/curl:8.10.1 -s "$@"; }

base_env=(-e MAUTIC_SITE_URL=$SITE -e MAUTIC_DB_HOST=$DB_HOST -e MAUTIC_DB_USER=$DB_USER
          -e MAUTIC_DB_PASSWORD=$DB_PASS -e MAUTIC_DB_NAME=$DB_NAME
          -e TRUSTED_PROXIES=172.16.0.0/12,192.168.0.0/16,10.0.0.0/8)
sso_env=(-e AUTH_TYPE=SSO -e MPASS_EDGE_SECRET=$SECRET -e MPASS_ALLOW_ANY_TENANT=1 -e SESSION_TTL_SECONDS=3600)

refuses() { # $1 label, $2 expected message fragment, rest: extra docker args
    local label=$1 want=$2; shift 2
    local out; out=$(docker run --rm --network "$NET" "${base_env[@]}" "$@" "$IMAGE" true 2>&1); local rc=$?
    check "$label" '[ $rc -ne 0 ] && grep -q "$want" <<<"$out"'
}

start() { # extra docker args
    docker rm -f "$NAME" >/dev/null 2>&1
    docker run -d --name "$NAME" --network "$NET" -v "$NAME-config:/var/www/html/config" "${base_env[@]}" "$@" "$IMAGE" >/dev/null
    for _ in $(seq 90); do
        docker logs "$NAME" 2>&1 | grep -q "resuming normal operations" && return 0
        docker ps -q --filter "name=^${NAME}$" --filter status=running | grep -q . || break
        sleep 2
    done
    docker logs "$NAME" 2>&1 | tail -20; return 1
}

echo "== entrypoint refusals"
refuses "no MPASS_EDGE_SECRET under SSO" "MPASS_EDGE_SECRET" -e AUTH_TYPE=SSO -e MPASS_ALLOW_ANY_TENANT=1
refuses "short MPASS_EDGE_SECRET under SSO" "MPASS_EDGE_SECRET" -e AUTH_TYPE=SSO -e MPASS_EDGE_SECRET=short -e MPASS_ALLOW_ANY_TENANT=1
refuses "no SMB_CORPORATE_ID and no MPASS_ALLOW_ANY_TENANT" "SMB_CORPORATE_ID" -e AUTH_TYPE=SSO -e MPASS_EDGE_SECRET=$SECRET
refuses "SESSION_TTL_SECONDS=0" "SESSION_TTL_SECONDS" "${sso_env[@]}" -e SESSION_TTL_SECONDS=0

echo "== first start, SSO on"
start "${sso_env[@]}" || { echo "container did not start"; exit 1; }
inside() { docker exec "$NAME" "$@"; }
# No admin email under SSO: the install admin is an unusable placeholder, and admins come only
# from the users script (baked into the image).
check "install admin is the .invalid placeholder" 'inside su -s /bin/sh www-data -c "php /opt/mautic-users.php list" | grep -q "mautic-install@admin.invalid .*\[admin\]"'
check "grant-admin via /opt/mautic-users.php" 'inside su -s /bin/sh www-data -c "php /opt/mautic-users.php grant-admin operator@image-test.example" | grep -q Administrator'

check "code is root-owned (index.php)" '[ "$(inside stat -c %U /var/www/html/index.php)" = root ]'
check "app/ is not writable by www-data" '! inside su -s /bin/sh www-data -c "test -w /var/www/html/app/config/security.php"'
check "config/, var/, media/, themes/, translations/ belong to www-data" \
      '[ "$(inside stat -c %U /var/www/html/config /var/www/html/var /var/www/html/media /var/www/html/themes /var/www/html/translations | sort -u)" = www-data ]'
check "no admin_* (and so no admin password) left in local.php" '! inside grep -q "admin_" /var/www/html/config/local.php'
check "no key/cert files in the image" '[ -z "$(inside find /var/www/html -name "*.key" -o -name "*.pem" -o -name "*.crt" | grep -v /vendor/ | head -1)" ]'

# 5.29: TTL wiring
check "5.29 session.gc_maxlifetime = SESSION_TTL_SECONDS" '[ "$(inside php -r "echo ini_get(\"session.gc_maxlifetime\");")" = 3600 ]'
check "5.29 session.cookie_lifetime = SESSION_TTL_SECONDS" '[ "$(inside php -r "echo ini_get(\"session.cookie_lifetime\");")" = 3600 ]'
check "5.29 session.gc_probability > 0" '[ "$(inside php -r "echo ini_get(\"session.gc_probability\");")" -gt 0 ]'

edge=(-H "Host: $HOST" -H "X-Forwarded-Proto: https" -H "X-Mpass-Edge-Secret: $SECRET" -H "X-Auth-Request-Email: operator@image-test.example")
page=$(curl_in -D - "${edge[@]}" "http://$NAME/s/account")
check "5.29 page mauticSessionLifetime = SESSION_TTL_SECONDS" 'grep -q "mauticSessionLifetime *= *\"3600\"" <<<"$page"'
# 5.26: cookie flags after the entrypoint warm-up; Request::isSecure() behind the trusted proxy
cookie=$(grep -i "^set-cookie:" <<<"$page" | grep -iv REMEMBERME | head -1)
check "5.26 session cookie is Secure" 'grep -qi "; secure" <<<"$cookie"'
check "5.26 session cookie is HttpOnly" 'grep -qi "; httponly" <<<"$cookie"'
check "5.26 session cookie is SameSite=Lax" 'grep -qi "samesite=lax" <<<"$cookie"'
check "5.26 cookie Max-Age = SESSION_TTL_SECONDS" 'grep -qi "max-age=3600" <<<"$cookie"'
# isSecure() behind the trusted proxy: with X-Forwarded-Proto https the request counts as secure
# (served); with http Mautic sends the visitor to https. (Symfony's own redirects are relative, so
# they cannot show the scheme.)
code=$(curl_in -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "X-Forwarded-Proto: https" "http://$NAME/mtc.js")
check "5.26 isSecure() true behind the proxy (X-Forwarded-Proto: https served)" '[ "$code" = 200 ]'
loc=$(curl_in -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $HOST" -H "X-Forwarded-Proto: http" "http://$NAME/mtc.js")
check "5.26 isSecure() false for X-Forwarded-Proto: http (sent to https)" '[[ "$loc" == 30?" https://$HOST/"* ]]'
loc=$(curl_in -o /dev/null -w '%{redirect_url}' -H "Host: $HOST" "http://$NAME/index.php/form/1")
check "Apache's /index.php/ 301 targets https://" '[[ "$loc" == https://$HOST/* ]]'

# Edge secret: an admin-UI request without it (from inside the network) is refused (R2-5).
forged=$(curl_in -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "X-Forwarded-Proto: https" -H "X-Auth-Request-Email: operator@image-test.example" "http://$NAME/s/account")
check "admin UI without the edge secret: 403" '[ "$forged" = 403 ]'
forged=$(curl_in -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "X-Mpass-Edge-Secret: wrong" -H "X-Auth-Request-Email: operator@image-test.example" "http://$NAME/s/account")
check "admin UI with a wrong edge secret: 403" '[ "$forged" = 403 ]'

# The edge secret is not in Apache's environment (phpinfo/env dumps), only in a www-data-readable file.
check "MPASS_EDGE_SECRET not in Apache's environment" '! inside sh -c "tr \"\\0\" \"\\n\" < /proc/1/environ" | grep -q "^MPASS_EDGE_SECRET="'
check "edge secret file is root:www-data 0440" '[ "$(inside stat -c "%U:%G %a" /run/mpass/edge-secret)" = "root:www-data 440" ]'
sysinfo=$(curl_in "${edge[@]}" "http://$NAME/s/sysinfo")
check "/s/sysinfo does not contain the edge secret" '! grep -q "$SECRET" <<<"$sysinfo"'
check "/s/sysinfo renders no phpinfo() under SSO" '! grep -q "apache2handler" <<<"$sysinfo"'

# Command mode (cron/worker containers): same image, volumes and SSO env, no install/warm-up.
out=$(docker run --rm --network "$NET" -v "$NAME-config:/var/www/html/config" "${base_env[@]}" "${sso_env[@]}" "$IMAGE" php -r 'echo getenv("AUTH_TYPE"), ":", posix_getpwuid(posix_geteuid())["name"];' 2>&1)
check "command mode runs the command as www-data with the SSO env" '[ "$out" = "SSO:www-data" ]'
out=$(docker run --rm --network "$NET" "${base_env[@]}" "${sso_env[@]}" "$IMAGE" php -r 'echo 1;' 2>&1); rc=$?
check "command mode refuses before the web container has installed" '[ $rc -ne 0 ] && grep -q "not installed yet" <<<"$out"'

echo "== 5.23: restart without AUTH_TYPE (prod container compiled without the flag)"
docker rm -f "$NAME" >/dev/null   # config/ (local.php) survives in the volume: no reinstall
start || { echo "container did not restart"; exit 1; }
check "5.23 authenticator registered in the prod container" 'inside su -s /bin/sh www-data -c "php bin/console debug:container \"Mautic\\UserBundle\\Security\\Authenticator\\MpassProxyAuthenticator\" --env=prod" >/dev/null 2>&1'
login=$(curl_in -H "Host: $HOST" "${edge[@]:2}" "http://$NAME/s/login")
check "5.23 inert without AUTH_TYPE: the password form is served" 'grep -q "name=\"_password\"" <<<"$login"'

docker rm -f "$NAME" >/dev/null
docker volume rm "$NAME-config" >/dev/null
echo "== $failures failure(s)"
exit $((failures > 0))
