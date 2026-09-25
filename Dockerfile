# syntax=docker/dockerfile:1
#
# Mautic behind the FOSS bundle's mPass SSO (oauth2-proxy + Traefik ForwardAuth).
# Build pattern B (prod): code, vendor and compiled assets are baked; no source mount.
# See sso-rules-moneta openspec/changes/add-mautic-to-sso/design.md §6.
#
# The Symfony container is NOT warmed at build time: app/config/config.php fixes the session
# cookie's `secure` flag from site_url when the container compiles, and site_url only exists at
# deploy time. docker/mpass/entrypoint.sh installs, renders config, then warms the cache.
#
# Web server: Apache with the repo's .htaccess files (they deny *.php other than index.php, .env*
# and media/files/). The image configures no HTTP auth in Apache, so the server never sets the
# CGI variable AUTH_TYPE, which would shadow the SSO flag of the same name.

ARG PHP_VERSION=8.2

FROM php:${PHP_VERSION}-apache AS base
ADD --chmod=0755 https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions /usr/local/bin/
RUN install-php-extensions intl pdo_mysql mysqli zip gd bcmath imap opcache sockets exif \
    && a2enmod rewrite headers \
    && rm -f /etc/apache2/sites-enabled/000-default.conf \
    && printf 'memory_limit = 512M\nexpose_php = Off\nzend.assertions = -1\n' > /usr/local/etc/php/conf.d/mautic.ini
COPY docker/mpass/apache-vhost.conf /etc/apache2/sites-enabled/mautic.conf
WORKDIR /var/www/html

FROM base AS build
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
COPY --from=node:20-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:20-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && apt-get update && apt-get install -y --no-install-recommends git unzip && rm -rf /var/lib/apt/lists/*
COPY . .
# Upstream's own release steps (build/package_release.php).
RUN composer install --no-dev --no-scripts --no-interaction --optimize-autoloader \
    && npm ci && npx patch-package \
    && php -d memory_limit=-1 bin/console mautic:assets:generate -e prod \
    && cd plugins/GrapesJsBuilderBundle && npm ci && npm run build
# Drop build-only files, and the prod container the asset command compiled (it baked
# cookie_secure=false because site_url did not exist yet).
RUN rm -rf node_modules plugins/GrapesJsBuilderBundle/node_modules plugins/GrapesJsBuilderBundle/.parcel-cache \
        var/cache/* var/logs/* config/local.php config/parameters_local.php \
    && ! ls .env.local* .env.prod* 2>/dev/null

FROM base AS runtime
COPY --from=build --chown=www-data:www-data /var/www/html /var/www/html
COPY --chmod=0755 docker/mpass/entrypoint.sh /usr/local/bin/mautic-entrypoint
ENV APP_ENV=prod APP_DEBUG=0
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s \
    CMD php -r 'exit(@file_get_contents("http://127.0.0.1/robots.txt") === false ? 1 : 0);'
ENTRYPOINT ["mautic-entrypoint"]
CMD ["apache2-foreground"]
