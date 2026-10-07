<?php

declare(strict_types=1);

namespace Mautic\UserBundle\EventListener;

use Mautic\UserBundle\Security\Authenticator\MpassProxyAuthenticator;
use Mautic\UserBundle\Security\Mpass\ProxyIdentity;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionFactoryInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Twig\Environment;

/**
 * Closes Mautic's local login doors under AUTH_TYPE=SSO (identity-surface-gating) and keeps the
 * Mautic session from being honoured outside the admin UI. Inert when AUTH_TYPE is not SSO.
 *
 * Rules key on the route name, not the path, so the /index.php/<path> twin of every route is
 * covered too. See sso-rules-moneta apps/mautic/security.md G1, G3, G4, G5, G11, G14.
 *
 * Deployment note: config_prod.php loads <local config dir>/config/security_local.php INSTEAD of
 * app/config/security.php when that file exists, which would drop the mPass authenticator. An SSO
 * deployment must never ship one.
 */
final readonly class MpassLocalAuthGuard implements EventSubscriberInterface
{
    public const REMEMBER_ME_COOKIE = 'REMEMBERME';

    /** Same pattern as the `main` firewall in app/config/security.php. */
    public const MAIN_FIREWALL_PATH = '#^/(s/|elfinder|efconnect)#';

    /** Routes that set a local password, create a user outside mPass, or issue a session → 404. */
    public const GATED_ROUTES = [
        'mautic_user_logincheck',
        'mautic_user_passwordreset',
        'mautic_user_passwordresetconfirm',
        'mautic_user_invite_register',
        'mautic_saml_login_retry',
        'mautic_sso_login',
        'mautic_sso_login_check',
        // The OAuth2 authorize flow's password form. /oauth/v2/token and /oauth/v2/authorize stay
        // open for API clients (the `api` firewall); clients allow no password grant.
        'mautic_oauth2_server_auth_login',
        'mautic_oauth2_server_auth_login_check',
    ];

    public const GATED_ROUTE_PREFIXES = [
        'lightsaml_sp.',
        'mautic_installer_',
        'mautic_api_users',
        'mautic_api_getself',
        'mautic_api_getuserroles',
        'mautic_api_checkpermission',
        'mautic_api_roles',
        '_api_/users', // API v2 (API Platform): POST/PUT/PATCH accept plainPassword and role
    ];

    public function __construct(
        private ProxyIdentity $identity,
        private UrlGeneratorInterface $urlGenerator,
        private Environment $twig,
        private ?string $portalUrl,
        private SessionFactoryInterface $sessionFactory,
        private LoggerInterface $logger,
        private ?string $rememberMePath = '/',
        private ?string $rememberMeDomain = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST  => [
                ['dropSessionOutsideMain', 129], // before the session listener (128)
                ['onRequest', 9],                // after routing (32), before the firewall (8)
            ],
            KernelEvents::RESPONSE => ['onResponse', 0],
            // Above the firewall's LoginThrottlingListener (0); copied onto the `main` firewall
            // dispatcher by RegisterGlobalSecurityEventListenersPass with its priority.
            LoginFailureEvent::class => ['keepRefusalsOutOfLoginThrottling', 64],
        ];
    }

    /**
     * login_throttling on `main` consumes a token on every LoginFailureEvent (Symfony 7.4's limiter
     * is peekable), including mPass refusals thrown before a passport exists. Refusals share the
     * per-IP global limiter, so 15 of them in 30 minutes from one address (every user, if
     * trusted_proxies is wrong) would lock out every SSO login from it. mPass refusals are not
     * password guesses: keep them out of the limiter.
     */
    public function keepRefusalsOutOfLoginThrottling(LoginFailureEvent $event): void
    {
        if ($event->getAuthenticator() instanceof MpassProxyAuthenticator) {
            $event->stopPropagation();
        }
    }

    /**
     * G14: outside the `main` firewall the Mautic session is not honoured. Tracking cookies are
     * left alone. Both the cookie bag and $_COOKIE are cleared: native session_start() reads the
     * latter.
     */
    public function dropSessionOutsideMain(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (!$event->isMainRequest() || !$this->identity->isSso()
            || preg_match(self::MAIN_FIREWALL_PATH, $this->path($request))) {
            return;
        }

        // The storage's own name (MAUTIC_SESSION_NAME in prod), read from an unstarted session.
        $name = $this->sessionFactory->createSession()->getName();
        $request->cookies->remove($name);
        unset($_COOKIE[$name]);
    }

    public function onRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (!$event->isMainRequest() || !$this->identity->isSso()) {
            return;
        }

        // G1: remember-me is disabled under SSO; the firewall never sees the cookie.
        if ($request->cookies->has(self::REMEMBER_ME_COOKIE)) {
            $request->cookies->remove(self::REMEMBER_ME_COOKIE);
            $request->attributes->set(MpassProxyAuthenticator::EXPIRE_REMEMBER_ME, true);
        }

        $response = $this->responseFor($request, (string) $request->attributes->get('_route'));
        if (null !== $response) {
            $event->setResponse($response);
        }
    }

    public function onResponse(ResponseEvent $event): void
    {
        if ($event->isMainRequest() && $event->getRequest()->attributes->get(MpassProxyAuthenticator::EXPIRE_REMEMBER_ME)) {
            $event->getResponse()->headers->clearCookie(self::REMEMBER_ME_COOKIE, $this->rememberMePath ?: '/', $this->rememberMeDomain ?: null);
        }
    }

    public static function isGatedRoute(string $route, Request $request): bool
    {
        if (in_array($route, self::GATED_ROUTES, true)) {
            return true;
        }
        foreach (self::GATED_ROUTE_PREFIXES as $prefix) {
            if (str_starts_with($route, $prefix)) {
                return true;
            }
        }

        // PHP method names are case-insensitive, so /s/users/INVITE also reaches inviteAction.
        return 'mautic_user_action' === $route && 'invite' === strtolower((string) $request->attributes->get('objectAction'));
    }

    private function responseFor(Request $request, string $route): ?Response
    {
        if (self::isGatedRoute($route, $request)) {
            return new Response('', Response::HTTP_NOT_FOUND); // G3, G4
        }

        // G11: no bearer/basic credential on the admin UI (`main` firewall), in the header or as the
        // `access_token` parameter FOSOAuthServer also reads: an OAuth2/basic login there would be a
        // second way into the UI, and every failed one would count against the login throttle of
        // the whole address. /api/* is left to Mautic's own `api` firewall, so API keys and OAuth
        // clients keep working under SSO (api_enabled stays an admin setting).
        if (preg_match(self::MAIN_FIREWALL_PATH, $this->path($request))
            && ($request->headers->has('Authorization')
                || $request->query->has('access_token')
                || $request->request->has('access_token'))) {
            return new Response('', Response::HTTP_UNAUTHORIZED);
        }

        // Round-2 review R2-5, when an edge secret is configured: every request to the admin UI that
        // came through the protected router carries it. One that does not came from inside the
        // network and is refused outright. Without a configured secret fromEdge() is always true.
        if (preg_match(self::MAIN_FIREWALL_PATH, $this->path($request)) && !$this->identity->fromEdge($request)) {
            $this->logger->warning('mPass SSO: admin-UI request without a valid edge secret refused', [
                'path'                => $this->path($request),
                'client_ip'           => $request->getClientIp(),
                'secret_header_given' => $request->headers->has(ProxyIdentity::EDGE_SECRET_HEADER), // never the value
            ]);

            return new Response('', Response::HTTP_FORBIDDEN);
        }

        // G5: per-app Logout is navigation-only; nothing is cleared. A missing or non-http(s)
        // LOGOUT_REDIRECT_URL is logged, and the static page is shown instead of a redirect.
        if ('mautic_user_logout' === $route) {
            $portal = ProxyIdentity::portalUrl($this->portalUrl);
            if (null === $portal) {
                $this->logger->error('mPass SSO: LOGOUT_REDIRECT_URL is missing or not an absolute http(s) URL; Logout does not redirect');

                return $this->mpassPage('logout');
            }

            return new RedirectResponse($portal);
        }

        // G5: no password form under SSO; the static page never redirects, so no loop.
        if ('login' === $route) {
            return '' !== $this->identity->asserted($request)
                ? new RedirectResponse($this->urlGenerator->generate('mautic_dashboard_index'))
                : $this->mpassPage('signin');
        }

        return null;
    }

    /**
     * The path as the firewall and router match it: they rawurldecode() the path info, so
     * `/%73/dashboard` is `/s/dashboard` to them and must be to us.
     */
    private function path(Request $request): string
    {
        return rawurldecode($request->getPathInfo());
    }

    private function mpassPage(string $reason): Response
    {
        return new Response($this->twig->render('@MauticUser/Security/mpass.html.twig', ['reason' => $reason]));
    }
}
