<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Functional\Mpass;

use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\EventListener\MpassLocalAuthGuard;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;

/**
 * identity-surface-gating, logout-flow and the Mautic-specific gaps G1, G3, G5, G11, G14
 * (sso-rules-moneta apps/mautic/security.md).
 */
final class MpassLocalAuthGuardTest extends AbstractMpassTestCase
{
    /** Every local-credential endpoint, called directly (task 3.12 / 5.16). */
    private const GATED_REQUESTS = [
        ['POST', '/s/login_check'],
        ['GET', '/passwordreset'],
        ['POST', '/passwordreset'],
        ['GET', '/passwordresetconfirm'],
        ['POST', '/passwordresetconfirm'],
        ['GET', '/invite/some-token'],
        ['POST', '/invite/some-token'],
        ['GET', '/s/saml/login'],
        ['POST', '/s/saml/login_check'],
        ['GET', '/saml/discovery'],
        ['GET', '/saml/metadata.xml'],
        ['GET', '/saml/login_retry'],
        ['GET', '/s/sso_login/Foo'],
        ['GET', '/s/sso_login_check/Foo'],
        ['GET', '/oauth/v2/authorize_login'],
        ['POST', '/oauth/v2/authorize_login_check'],
        ['POST', '/s/users/invite'],
        ['POST', '/s/users/INVITE'], // PHP method names are case-insensitive
        ['POST', '/api/users/new'],
    ];

    /**
     * Routes whose controller sets a credential or which the firewall handles, and which stay
     * reachable under SSO for a stated reason (task 5.17).
     */
    private const ALLOWED = [
        'login'               => 'guard: redirects to the dashboard or renders the static mPass page',
        'mautic_user_logout'  => 'guard: 302 to LOGOUT_REDIRECT_URL, clears nothing',
        'mautic_user_account' => 'ProfileController drops plainPassword and email under SSO',
        'mautic_user_action'  => 'new/edit drop plainPassword (and email on edit) under SSO; invite is gated',
        'mautic_user_index'   => 'list only; the invite button is hidden under SSO',
        // Bundle-contract review: API keys and OAuth clients keep working under SSO. Clients allow
        // no password grant, and the authorize flow's password form stays gated.
        'fos_oauth_server_token'     => 'the `api` firewall; client_credentials/auth-code/refresh only',
        'fos_oauth_server_authorize' => 'needs a login through mautic_oauth2_server_auth_login, which is gated',
    ];

    public function testLocalCredentialEndpoints404UnderSso(): void
    {
        $admin    = $this->findUser('admin@yoursite.com');
        $password = $admin->getPassword();
        $count    = $this->userCount();

        foreach (self::GATED_REQUESTS as [$method, $path]) {
            $response = $this->get($path, null, [], $method);
            $this->assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode(), "{$method} {$path}");
            $this->assertFalse($response->headers->has('Set-Cookie') && str_contains((string) $response->headers->get('Set-Cookie'), 'REMEMBERME='), "{$method} {$path} issued no credential");
        }

        $this->assertSame($password, $this->reload($admin)->getPassword(), 'no password changed');
        $this->assertSame($count, $this->userCount(), 'no user created');
    }

    public function testIndexPhpPrefixIsGated(): void
    {
        $server = ['SCRIPT_NAME' => '/index.php', 'SCRIPT_FILENAME' => '/app/index.php'];
        $this->assertSame(Response::HTTP_NOT_FOUND, $this->get('/index.php/passwordreset', null, $server)->getStatusCode());

        $this->restartWithEnv('AUTH_TYPE', null);
        $this->assertSame(Response::HTTP_OK, $this->get('/index.php/passwordreset', null, $server)->getStatusCode(), 'the prefixed path does resolve to the route');
    }

    public function testInertWhenAuthTypeUnset(): void
    {
        $this->restartWithEnv('AUTH_TYPE', null);

        $this->assertSame(Response::HTTP_OK, $this->get('/passwordreset', null)->getStatusCode());
        $login = $this->get('/s/login', 'alice@example.com');
        $this->assertSame(Response::HTTP_OK, $login->getStatusCode());
        $this->assertStringContainsString('name="_password"', (string) $login->getContent(), 'the password form is served');
        $this->assertSame(Response::HTTP_FOUND, $this->get('/s/logout', null)->getStatusCode());
        $this->assertStringEndsWith('/s/login', (string) $this->client->getResponse()->headers->get('Location'), 'upstream logout');
    }

    public function testRouteInventory(): void
    {
        // Credential setters, session issuers and OAuth2 token minting.
        $issuers   = '/->(setPassword|checkNewPassword|hashPassword|createInvite|setToken|grantAccessToken|createAccessToken)\(|->loginUser\(/';
        $unguarded = [];
        $sensitive = [];

        foreach (self::getContainer()->get(RouterInterface::class)->getRouteCollection() as $name => $route) {
            $controller = $route->getDefault('_controller');
            $class      = is_string($controller) ? explode('::', $controller)[0] : null;
            if (null !== $class && !class_exists($class) && self::getContainer()->has($class)) {
                $class = self::getContainer()->get($class)::class; // controller given as a service id
            }
            $isSensitive = null === $controller && preg_match(MpassLocalAuthGuard::MAIN_FIREWALL_PATH, $route->getPath()) // firewall-handled
                || (null !== $class && class_exists($class) && preg_match($issuers, (string) file_get_contents((new \ReflectionClass($class))->getFileName())))
                || (User::class === $route->getDefault('_api_resource_class') && array_intersect($route->getMethods(), ['POST', 'PUT', 'PATCH']));

            if ($isSensitive) {
                $sensitive[] = $name;
            }
            if ($isSensitive && !MpassLocalAuthGuard::isGatedRoute($name, new Request()) && !isset(self::ALLOWED[$name])) {
                $unguarded[] = $name.' ('.$route->getPath().')';
            }
        }

        $this->assertSame([], $unguarded, 'credential-setting or session-issuing routes that are neither gated nor allow-listed');
        $this->assertContains('fos_oauth_server_token', $sensitive, 'the inventory sees OAuth2 token minting');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function gatedRequests(): iterable
    {
        foreach (self::GATED_REQUESTS as [$method, $path]) {
            yield "{$method} {$path}" => [$method, $path];
        }
    }

    /**
     * identity-surface-gating §"The gate does not affect non-SSO deployments", per endpoint:
     * without AUTH_TYPE the guard's empty 404 never appears (upstream answers, whatever it says).
     */
    #[DataProvider('gatedRequests')]
    public function testGatedEndpointIsUpstreamWithoutSso(string $method, string $path): void
    {
        $this->restartWithEnv('AUTH_TYPE', null);

        $response = $this->get($path, null, [], $method);

        $this->assertFalse(Response::HTTP_NOT_FOUND === $response->getStatusCode() && '' === $response->getContent(), "{$method} {$path} was refused by the SSO guard");
    }

    // --- review findings 3 and 4 --------------------------------------------------------------

    public function testOauthAccessTokenParameterIsRefusedOnTheAdminUiUnderSso(): void
    {
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->get('/s/account?access_token=x', null)->getStatusCode(), 'query');
        $this->client->request('POST', '/s/account', ['access_token' => 'x']);
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode(), 'body');
        // (API v2 user routes answer 404 before any credential check: they are gated routes.)
        $this->assertSame(Response::HTTP_NOT_FOUND, $this->get('/api/v2/users', null, ['PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'Maut1cR0cks!'], 'POST')->getStatusCode(), 'API v2 user write');
    }

    /**
     * Bundle-contract review: the REST API is Mautic's own `api` firewall's business, so API keys
     * and OAuth clients keep working under SSO. The guard's refusal is an empty 401; whatever the
     * API answers, it is not that.
     */
    public function testApiCredentialsReachTheApiFirewallUnderSso(): void
    {
        foreach ([
            'API query'  => $this->get('/api/contacts?access_token=x', null),
            'API bearer' => $this->get('/api/contacts', null, ['HTTP_AUTHORIZATION' => 'Bearer x']),
            'API basic'  => $this->get('/api/v2/docs.json', null, ['PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'Maut1cR0cks!']),
            'token'      => $this->get('/oauth/v2/token', null, [], 'POST'),
        ] as $label => $response) {
            $this->assertFalse(in_array($response->getStatusCode(), [Response::HTTP_UNAUTHORIZED, Response::HTTP_NOT_FOUND], true) && '' === $response->getContent(), "{$label} was refused by the SSO guard");
        }
    }

    public function testEncodedPathCannotSkipTheCredentialCheck(): void
    {
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->get('/%73/account', null, ['HTTP_AUTHORIZATION' => 'Bearer x'])->getStatusCode());
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->get('/%73/account?access_token=x', null)->getStatusCode());
    }

    public function testBogusAccessTokensDoNotLockOutAnMpassLogin(): void
    {
        for ($i = 0; $i < 20; ++$i) {
            $this->client->getCookieJar()->clear();
            $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->get('/s/account?access_token=bogus'.$i, null)->getStatusCode());
        }

        $this->client->getCookieJar()->clear();
        $this->createUser('alice@example.com');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
    }

    // --- review finding 13 ---------------------------------------------------------------------

    public function testAdminCreateAndEditStoreLowercaseEmails(): void
    {
        $this->createUser('alice@example.com');
        $legacy = $this->createUser('Legacy.User@Example.COM', username: 'legacy');
        $this->get('/s/account', 'alice@example.com');

        $this->submitWithExtras('/s/users/new', [
            'email'     => '  Carol.New@Example.COM ',
            'firstName' => 'Carol',
            'lastName'  => 'Example',
            'role'      => (string) $this->memberRole->getId(),
        ]);
        $carol = $this->findUser('carol.new@example.com');
        $this->assertInstanceOf(User::class, $carol, 'stored lowercase and trimmed');
        $this->assertSame('carol.new@example.com', $carol->getUserIdentifier());

        $this->restart();
        $this->submitWithExtras('/s/users/edit/'.$legacy->getId(), ['firstName' => 'Legacy']);
        $this->assertSame('legacy.user@example.com', $this->reload($legacy)->getEmail());
    }

    public function testAuthorizationHeaderRefusedOnMainUnderSso(): void
    {
        $this->createUser('alice@example.com');

        $response = $this->get('/s/account', 'alice@example.com', ['HTTP_AUTHORIZATION' => 'Bearer x']);

        $this->assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->findUser('alice@example.com')->getLastLogin(), 'no authentication happened');
    }

    public function testLogoutLinkIsPortalAndLogoutRouteClearsNothing(): void
    {
        $this->restartWithEnv('LOGOUT_REDIRECT_URL', 'https://foss.example.test');
        $this->createUser('alice@example.com');
        $page = $this->get('/s/account', 'alice@example.com');
        $this->assertStringContainsString('href="https://foss.example.test"', (string) $page->getContent());
        $this->assertStringNotContainsString('/s/logout', (string) $page->getContent());
        $session = $this->sessionId();

        $response = $this->get('/s/logout', 'alice@example.com');

        $this->assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertSame('https://foss.example.test', $response->headers->get('Location'));
        $this->assertSame($session, $this->sessionId(), 'the session cookie is unchanged');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', null));
    }

    /**
     * A missing or non-http(s) LOGOUT_REDIRECT_URL is never redirected to: the menu keeps the
     * logout route, whose guard shows the static page.
     */
    public function testInvalidLogoutRedirectUrlIsNotFollowed(): void
    {
        $this->createUser('alice@example.com');
        foreach ([null, '', '/', 'foss.example.test', 'javascript:alert(1)'] as $url) {
            $this->restartWithEnv('LOGOUT_REDIRECT_URL', $url);

            $page = $this->get('/s/account', 'alice@example.com');
            $this->assertStringContainsString('/s/logout', (string) $page->getContent(), var_export($url, true));

            $response = $this->get('/s/logout', 'alice@example.com');
            $this->assertSame(Response::HTTP_OK, $response->getStatusCode(), var_export($url, true));
            $this->assertFalse($response->headers->has('Location'), var_export($url, true));
        }
    }

    public function testLoginPageNeverLoops(): void
    {
        $this->createUser('alice@example.com');
        $this->createUser('bob@example.com', published: false);

        $toApp = $this->get('/s/login', 'alice@example.com');
        $this->assertSame(Response::HTTP_FOUND, $toApp->getStatusCode());
        $this->assertStringEndsWith('/s/dashboard', (string) $toApp->headers->get('Location'));

        $landing = $this->get('/s/login', null);
        $this->assertSame(Response::HTTP_OK, $landing->getStatusCode());
        $this->assertStringContainsString('data-reason="signin"', (string) $landing->getContent());
        $this->assertStringNotContainsString('_password', (string) $landing->getContent());

        $this->client->getCookieJar()->clear();
        $this->get('/s/login', 'bob@example.com');
        $refused = $this->get((string) $this->client->getResponse()->headers->get('Location'), 'bob@example.com');
        $this->assertRefused('inactive', $refused);
    }

    public function testRememberMeDoesNotResurrectPreviousUser(): void
    {
        // Mint a genuine REMEMBERME for admin through the password login, SSO off.
        $this->restartWithEnv('AUTH_TYPE', null);
        $crawler = $this->client->request('GET', '/s/login');
        $form    = $crawler->filter('form')->form(['_username' => 'admin', '_password' => 'Maut1cR0cks!', '_remember_me' => true]);
        $this->client->submit($form);
        $rememberMe = $this->client->getCookieJar()->get('REMEMBERME');
        $this->assertInstanceOf(Cookie::class, $rememberMe, 'precondition: a remember-me cookie was issued');

        // Control: with SSO off the cookie alone restores admin.
        $this->client->getCookieJar()->clear();
        $this->client->getCookieJar()->set(new Cookie('REMEMBERME', $rememberMe->getValue()));
        $this->assertServedAs('admin', $this->get('/s/account', null));

        // Under SSO, A's cookie with B's header is served as B, and the cookie is expired.
        $this->restartWithEnv('AUTH_TYPE', 'SSO');
        $this->createUser('bob@example.com');
        $this->client->getCookieJar()->clear();
        $this->client->getCookieJar()->set(new Cookie('REMEMBERME', $rememberMe->getValue()));
        $response = $this->get('/s/account', 'bob@example.com');
        $this->assertServedAs('bob@example.com', $response);
        $this->assertStringContainsString('REMEMBERME=deleted', implode("\n", $response->headers->all('set-cookie')));

        // And A's cookie with no header and no session is not honoured at all.
        $this->client->getCookieJar()->clear();
        $this->client->getCookieJar()->set(new Cookie('REMEMBERME', $rememberMe->getValue()));
        $response = $this->get('/s/account', null);
        $this->assertAnonymous($response);
        $this->assertStringContainsString('REMEMBERME=deleted', implode("\n", $response->headers->all('set-cookie')));
    }

    public function testRefusalsDoNotConsumeLoginThrottling(): void
    {
        for ($i = 0; $i < 20; ++$i) {
            $this->client->getCookieJar()->clear();
            $this->assertRefused('unresolvable', $this->get('/s/account', '1020010000019120'));
        }

        $this->client->getCookieJar()->clear();
        $this->createUser('alice@example.com');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
    }

    public function testBypassedPathWithLiveSessionIsAnonymous(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $this->assertServedAs('alice@example.com', $this->get('/s/account', null));

        // PageModel skips hits for logged-in users ("don't skew results with user hits").
        $this->assertHitsRecorded(1, 'the session is not honoured on the public firewall');

        $this->restartWithEnv('AUTH_TYPE', null);
        $this->assertHitsRecorded(0, 'upstream behaviour without SSO');
    }

    public function testProfileAndAdminEditCannotChangePasswordOrEmail(): void
    {
        $alice = $this->createUser('alice@example.com');
        $bob   = $this->createUser('bob@example.com');
        $this->get('/s/account', 'alice@example.com');

        $this->submitWithExtras('/s/account', ['plainPassword' => ['password' => 'N3w-Passw0rd!', 'confirm' => 'N3w-Passw0rd!'], 'email' => 'evil@example.com']);
        $this->submitWithExtras('/s/users/edit/'.$bob->getId(), ['plainPassword' => ['password' => 'N3w-Passw0rd!', 'confirm' => 'N3w-Passw0rd!'], 'email' => 'evil2@example.com']);

        foreach ([$alice, $bob] as $user) {
            $fresh = $this->reload($user);
            $this->assertSame('unused', $fresh->getPassword(), $user->getEmail().' password unchanged');
            $this->assertSame($user->getEmail(), $fresh->getEmail(), $user->getEmail().' email unchanged');
        }
    }

    public function testUsernameIsLockedToEmailUnderSso(): void
    {
        $alice = $this->createUser('alice@example.com');
        $bob   = $this->createUser('bob@example.com');
        $this->get('/s/account', 'alice@example.com');

        // Claiming a colleague's email as username would block their first mPass login.
        $this->submitWithExtras('/s/account', ['username' => 'carol@example.com']);
        $this->submitWithExtras('/s/users/edit/'.$bob->getId(), ['username' => 'carol@example.com']);
        $this->assertSame('alice@example.com', $this->reload($alice)->getUserIdentifier());
        $this->assertSame('bob@example.com', $this->reload($bob)->getUserIdentifier());

        $this->restart();
        $this->submitWithExtras('/s/users/new', [
            'username'  => 'carol@example.com',
            'email'     => 'dave@example.com',
            'firstName' => 'Dave',
            'lastName'  => 'Example',
            'role'      => (string) $this->memberRole->getId(),
        ]);
        $this->assertSame('dave@example.com', $this->findUser('dave@example.com')?->getUserIdentifier());
    }

    public function testProfileSaveStillWorksUnderSso(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->get('/s/account', 'alice@example.com');

        $this->submitWithExtras('/s/account', ['firstName' => 'Alicia']);

        $this->assertSame('Alicia', $this->reload($alice)->getFirstName());
    }

    public function testAdminCreateIgnoresSubmittedPassword(): void
    {
        $this->createUser('alice@example.com');
        $this->get('/s/account', 'alice@example.com');

        $carol = [
            'username'  => 'carol@example.com',
            'email'     => 'carol@example.com',
            'firstName' => 'Carol',
            'lastName'  => 'Example',
            'role'      => (string) $this->memberRole->getId(),
        ];
        $known  = ['password' => 'Kn0wn-Passw0rd!', 'confirm' => 'Kn0wn-Passw0rd!'];
        $hasher = self::getContainer()->get(\Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface::class);

        // A direct POST carrying a password: the field does not exist under SSO, so it never lands.
        $this->submitWithExtras('/s/users/new', $carol + ['plainPassword' => $known]);
        $created = $this->findUser('carol@example.com');
        $this->assertTrue(null === $created || !$hasher->isPasswordValid($created, $known['password']), 'the submitted password was not set');

        // The UI's own submit (no password field) pre-provisions the user with a random password.
        $this->restart();
        $this->submitWithExtras('/s/users/new', $carol);
        $created = $this->findUser('carol@example.com');
        $this->assertInstanceOf(User::class, $created, 'pre-provisioning by email still works');
        $this->assertNotEmpty($created->getPassword());
        $this->assertFalse($hasher->isPasswordValid($created, $known['password']));
    }

    public function testAdminCreateWithArrayEmailDoesNotCrash(): void
    {
        $this->createUser('alice@example.com');
        $this->get('/s/account', 'alice@example.com');

        $this->submitWithExtras('/s/users/new', ['email' => ['x@example.com']]);

        $this->assertNotInstanceOf(User::class, $this->findUser('x@example.com'));
    }

    /**
     * Submits the `user` form found at $path with extra/overridden fields, including fields the
     * rendered form does not have (a direct POST, bypassing the UI).
     *
     * @param array<string, mixed> $fields
     * @param string[]             $dropFromRendered
     */
    private function submitWithExtras(string $path, array $fields, array $dropFromRendered = []): void
    {
        $crawler = $this->client->request('GET', $path, [], [], ['HTTP_X_AUTH_REQUEST_EMAIL' => 'alice@example.com', 'HTTP_X_MPASS_EDGE_SECRET' => self::EDGE_SECRET]);
        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode(), $path);
        $values = $crawler->filter('form[name=user]')->form()->getPhpValues();
        foreach ($dropFromRendered as $name) {
            unset($values['user'][$name]);
        }
        $values['user'] = array_replace($values['user'], $fields);
        $values['user']['buttons']['save'] = '';

        $this->client->request('POST', $path, $values, [], ['HTTP_X_AUTH_REQUEST_EMAIL' => 'alice@example.com', 'HTTP_X_MPASS_EDGE_SECRET' => self::EDGE_SECRET]);
        $this->assertLessThan(500, $this->client->getResponse()->getStatusCode(), "POST {$path} must not crash");
    }

    private function assertHitsRecorded(int $expected, string $message): void
    {
        $table  = MAUTIC_TABLE_PREFIX.'page_hits';
        $before = (int) $this->connection->fetchOne("SELECT COUNT(*) FROM {$table}");
        $this->get('/mtracking.gif', null);
        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        $this->assertSame($expected, (int) $this->connection->fetchOne("SELECT COUNT(*) FROM {$table}") - $before, $message);
    }
}
