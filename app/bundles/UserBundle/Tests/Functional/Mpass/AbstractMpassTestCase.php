<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Functional\Mpass;

use Mautic\CoreBundle\Test\MauticMysqlTestCase;
use Mautic\UserBundle\Entity\Role;
use Mautic\UserBundle\Entity\User;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Shared harness for the mPass SSO functional tests. Every request goes through the real kernel.
 *
 * %env()% values are resolved once per container instance, i.e. once per request in production.
 * A test simulates "the next request with a different env" by rebooting the already compiled
 * kernel, which is why the rollback cleanup is off.
 */
abstract class AbstractMpassTestCase extends MauticMysqlTestCase
{
    protected $useCleanupRollback = false;

    private const ENV = ['AUTH_TYPE', 'MPASS_SSO_DEFAULT_ROLE', 'DEFAULT_EMAIL_DOMAIN', 'SMB_CORPORATE_ID', 'MPASS_PORTAL_URL', 'MPASS_EDGE_SECRET', 'MPASS_EDGE_SECRET_FILE', 'MPASS_ALLOW_ANY_TENANT'];

    /** What the protected Traefik router injects; tests send it wherever the edge would. */
    protected const EDGE_SECRET = 'test-edge-secret-0123456789abcdef0123456789';

    protected Role $adminRole;

    protected Role $memberRole;

    protected function setUp(): void
    {
        self::setEnv('AUTH_TYPE', 'SSO');
        self::setEnv('MPASS_EDGE_SECRET', self::EDGE_SECRET);
        // Tests run with SMB_CORPORATE_ID empty unless they set it; say so, as a deployment must.
        self::setEnv('MPASS_ALLOW_ANY_TENANT', '1');
        parent::setUp();

        $this->adminRole  = $this->createRole('mPass test admins', true);
        $this->memberRole = $this->createRole('mPass test members', false);
        self::setEnv('MPASS_SSO_DEFAULT_ROLE', (string) $this->memberRole->getId());
        $this->restart();
        $this->client->getCookieJar()->clear(); // start anonymous (the base class logs in admin)
    }

    protected function beforeTearDown(): void
    {
        foreach (self::ENV as $name) {
            self::setEnv($name, null);
        }
    }

    protected static function setEnv(string $name, ?string $value): void
    {
        if (null === $value) {
            unset($_ENV[$name], $_SERVER[$name]);
            putenv($name);

            return;
        }
        $_ENV[$name] = $_SERVER[$name] = $value;
        putenv("{$name}={$value}");
    }

    protected function restartWithEnv(string $name, ?string $value): void
    {
        self::setEnv($name, $value);
        $this->restart();
    }

    protected function restart(): void
    {
        $cookies = $this->client->getCookieJar()->all();
        $this->setUpSymfony($this->configParams);
        $this->client->followRedirects(false);
        foreach ($cookies as $cookie) {
            $this->client->getCookieJar()->set($cookie);
        }
    }

    /**
     * @param array<string, string> $server
     */
    protected function get(string $path, ?string $email, array $server = [], string $method = 'GET'): Response
    {
        if (null !== $email) {
            $server['HTTP_X_AUTH_REQUEST_EMAIL'] = $email;
        }
        // The protected router adds the edge secret to every request it forwards, with or without
        // an identity. A caller may override it ('' = absent, as from inside the network).
        $server += ['HTTP_X_MPASS_EDGE_SECRET' => self::EDGE_SECRET];
        $this->client->request($method, $path, [], [], $server);

        return $this->client->getResponse();
    }

    protected function assertServedAs(string $username, Response $response): void
    {
        self::assertSame(Response::HTTP_OK, $response->getStatusCode(), 'Location: '.$response->headers->get('Location').' '.substr(strip_tags((string) $response->getContent()), 0, 300));
        self::assertMatchesRegularExpression('/LoginUserName\s*=\s*\''.preg_quote(str_replace('@', '\\u0040', $username), '/').'\'/', (string) $response->getContent());
    }

    protected function assertRefused(string $reason, Response $response, string $message = ''): void
    {
        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), $message);
        self::assertStringContainsString('data-reason="'.$reason.'"', (string) $response->getContent(), $message);
        self::assertFalse($response->headers->has('Location'), 'no redirect, so no loop');
    }

    protected function assertAnonymous(Response $response): void
    {
        self::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), 'anonymous → entry point');
        self::assertStringEndsWith('/s/login', (string) $response->headers->get('Location'));
    }

    /** Replaying the previous user's session cookie with no header must not serve them. */
    protected function assertOldSessionIsGone(string $oldSessionId): void
    {
        $this->client->getCookieJar()->clear();
        $this->client->getCookieJar()->set(new Cookie($this->sessionName(), $oldSessionId));

        $this->assertAnonymous($this->get('/s/account', null));
    }

    protected function sessionName(): string
    {
        return (string) static::getContainer()->get('session.factory')->createSession()->getName();
    }

    protected function sessionId(): ?string
    {
        $value = null; // the jar may hold one cookie per domain; the last one set wins
        foreach ($this->client->getCookieJar()->all() as $cookie) {
            if ($cookie->getName() === $this->sessionName()) {
                $value = $cookie->getValue();
            }
        }

        return $value;
    }

    protected function createRole(string $name, bool $admin, bool $published = true): Role
    {
        $role = new Role();
        $role->setName($name);
        $role->setIsAdmin($admin);
        $role->setIsPublished($published);
        $this->em->persist($role);
        $this->em->flush();

        return $role;
    }

    protected function createUser(string $email, ?string $username = null, bool $published = true, ?Role $role = null): User
    {
        $user = new User();
        $user->setEmail($email);
        $user->setUsername($username ?? strtolower($email));
        $user->setFirstName('Test');
        $user->setLastName('User');
        $user->setRole($this->em->getReference(Role::class, ($role ?? $this->adminRole)->getId()));
        $user->setPassword('unused');
        $user->setIsPublished($published);
        $this->em->persist($user);
        $this->em->flush();

        return $user;
    }

    protected function findUser(string $email): ?User
    {
        $this->em->clear();

        return $this->em->getRepository(User::class)->findOneBy(['email' => $email]);
    }

    protected function reload(?User $user): User
    {
        self::assertNotNull($user);
        $this->em->clear();

        return $this->em->find(User::class, $user->getId());
    }

    protected function userCount(): int
    {
        $this->em->clear();

        return $this->em->getRepository(User::class)->count([]);
    }
}
