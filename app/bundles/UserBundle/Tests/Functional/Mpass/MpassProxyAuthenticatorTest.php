<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Functional\Mpass;

use Mautic\UserBundle\Entity\Role;
use Mautic\UserBundle\Model\RoleModel;
use Mautic\UserBundle\Security\Authenticator\MpassProxyAuthenticator;
use Symfony\Component\HttpFoundation\Response;

/**
 * proxy-auth-middleware contract (sso-rules-moneta openspec/specs/proxy-auth-middleware/spec.md).
 * The first six tests are the mandatory cases, named after Plane's test_proxy_auth.py.
 */
final class MpassProxyAuthenticatorTest extends AbstractMpassTestCase
{
    // --- the six mandatory cases ---------------------------------------------------------------

    public function testMatchShortCircuits(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
        self::assertSame($before, $this->sessionId(), 'no new session id');
        self::assertNull($this->reload($alice)->getLastLogin(), 'no users write: authenticate() never ran');
    }

    public function testNoLogoutWhenHeaderAbsent(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', null));
        self::assertSame($before, $this->sessionId());
    }

    public function testMatchIsCaseAndWhitespaceInsensitive(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', '  ALICE@Example.COM  '));
        self::assertSame($before, $this->sessionId());
        self::assertNull($this->reload($alice)->getLastLogin());
    }

    public function testMismatchFlushesAndReauths(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->createUser('bob@example.com');
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();

        $this->assertServedAs('bob@example.com', $this->get('/s/account', 'bob@example.com'));
        self::assertNotSame($aliceSession, $this->sessionId(), 'session id changed');
        $this->assertOldSessionIsGone($aliceSession);
    }

    public function testMismatchWithInactiveIncomingUser(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->createUser('bob@example.com', published: false);
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();

        // Deliberate deviation (design.md §3): a 403 page instead of "proceeds as AnonymousUser".
        $this->assertRefused('inactive', $this->get('/s/account', 'bob@example.com'));
        $this->assertOldSessionIsGone($aliceSession);
    }

    public function testBypassDominatesMismatch(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->createUser('bob@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->get('/mtracking.gif', 'bob@example.com');
        $this->get('/form/submit', 'bob@example.com', [], 'POST');

        self::assertSame($before, $this->sessionId(), 'no flush on the public firewall');
        self::assertNull($this->findUser('bob@example.com')->getLastLogin(), 'no login on the public firewall');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', null));
    }

    // --- Rule 3 / provisioning -----------------------------------------------------------------

    public function testFirstSeenEmailIsProvisionedWithDefaultRoleAndNames(): void
    {
        $this->get('/s/account', 'newcomer@example.com');

        $user = $this->findUser('newcomer@example.com');
        self::assertNotNull($user);
        self::assertSame('newcomer@example.com', $user->getUserIdentifier());
        self::assertSame('newcomer', $user->getFirstName());
        self::assertSame('example.com', $user->getLastName());
        self::assertSame($this->memberRole->getId(), $user->getRole()->getId());
        self::assertTrue($user->isPublished());
        self::assertNotEmpty($user->getPassword());
        self::assertNotNull($user->getLastLogin(), 'InteractiveLoginEvent fired');
    }

    public function testRolePermissionsApplyOnTheFirstRequest(): void
    {
        $role = $this->em->find(Role::class, $this->memberRole->getId());
        static::getContainer()->get(RoleModel::class)->setRolePermissions($role, ['user:users' => ['view']]);
        $this->em->persist($role);
        $this->em->flush();

        // The login request itself, not the next one that reloads the user from the session.
        self::assertSame(Response::HTTP_OK, $this->get('/s/users', 'newcomer@example.com')->getStatusCode());
    }

    public function testMixedCaseHeaderResolvesExistingUser(): void
    {
        $this->createUser('Alice@Example.com');
        $count = $this->userCount();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'ALICE@example.COM'));
        self::assertSame($count, $this->userCount());
    }

    public function testDisplayNameIsNeverTheSub(): void
    {
        $this->restartWithEnv('DEFAULT_EMAIL_DOMAIN', 'corp.example');
        $sub = '892ae5ac-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
        $this->get('/s/account', '1020010000019120', ['HTTP_X_AUTH_REQUEST_USER' => $sub]);

        $user = $this->findUser('1020010000019120@corp.example');
        self::assertNotNull($user);
        self::assertSame('1020010000019120', $user->getFirstName());
        self::assertSame('corp.example', $user->getLastName());
        self::assertNull($this->findUser($sub));
    }

    public function testSqlWildcardsAreLiteral(): void
    {
        $victim = $this->createUser('victim@example.com');

        $this->get('/s/account', 'v%@example.com');

        self::assertNotNull($this->findUser('v%@example.com'), 'a new user, not the victim');
        self::assertNull($this->reload($victim)->getLastLogin());
    }

    public function testUsernameEqualToHeaderEmailDoesNotImpersonate(): void
    {
        $x     = $this->createUser('x@example.com', username: 'bob@corp.com');
        $count = $this->userCount();

        $this->assertRefused('conflict', $this->get('/s/account', 'bob@corp.com'));
        self::assertSame($count, $this->userCount());
        self::assertNull($this->reload($x)->getLastLogin(), 'X was not logged in');
    }

    public function testUniqueViolationFallsBackToRead(): void
    {
        // Simulates losing the INSERT race: the row appears between the lookup and the flush.
        $count = $this->userCount();
        $this->createUser('racer@example.com', username: 'racer@example.com', role: $this->memberRole);
        $connection = $this->connection;
        $table      = MAUTIC_TABLE_PREFIX.'users';
        $connection->executeStatement("UPDATE {$table} SET email = 'RACER-PENDING' WHERE email = 'racer@example.com'");

        $listener = function () use ($connection, $table): void {
            $connection->executeStatement("UPDATE {$table} SET email = 'racer@example.com' WHERE email = 'RACER-PENDING'");
        };
        static::getContainer()->get('event_dispatcher')->addListener(\Mautic\UserBundle\UserEvents::USER_PRE_SAVE, $listener);

        $response = $this->get('/s/account', 'racer@example.com');

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame($count + 1, $this->userCount(), 'no duplicate row');
    }

    public function testUnresolvableIdentityFlushes(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();
        $count        = $this->userCount();

        $this->assertRefused('unresolvable', $this->get('/s/account', '1020010000019120')); // no DEFAULT_EMAIL_DOMAIN
        self::assertSame($count, $this->userCount());
        $this->assertOldSessionIsGone($aliceSession);
    }

    public function testXAuthRequestUserIsNeverUsed(): void
    {
        $count = $this->userCount();

        $this->assertAnonymous($this->get('/s/account', '   ', ['HTTP_X_AUTH_REQUEST_USER' => '892ae5ac-1c2d-4e5f-8a9b-0c1d2e3f4a5b']));
        self::assertSame($count, $this->userCount());
    }

    public function testDefaultRoleGuard(): void
    {
        $count = $this->userCount();
        $cases = [
            'unset'       => '',
            'missing'     => '999999',
            'admin'       => (string) $this->adminRole->getId(),
            'unpublished' => (string) $this->createRole('mPass unpublished', false, false)->getId(),
            'name'        => 'mPass test members',
        ];

        foreach ($cases as $case => $value) {
            $this->restartWithEnv('MPASS_SSO_DEFAULT_ROLE', $value);
            $this->assertRefused('role', $this->get('/s/account', "role-{$case}@example.com"), $case);
            self::assertSame($count, $this->userCount(), $case);
        }
    }

    public function testExistingUserIsNeverReRoled(): void
    {
        $alice = $this->createUser('alice@example.com');

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
        self::assertSame($this->adminRole->getId(), $this->reload($alice)->getRole()->getId());
    }

    // --- corporate-tenant binding (audit row 22) ----------------------------------------------

    public function testCorporateUnsetSkipsCheck(): void
    {
        $this->createUser('alice@example.com');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
    }

    public function testCorporateMatchingPrincipalIsAdmitted(): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42');
        $this->createUser('alice@example.com');

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com', $this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42'])));
    }

    public function testCorporateIndividualPrincipalIsRefused(): void
    {
        $this->assertCorporateRefusal($this->token(['custom:is_corporate' => 'false', 'custom:corporate_id' => 'acme-42']));
        $this->assertCorporateRefusal($this->token(['custom:corporate_id' => 'acme-42']));
    }

    public function testCorporateOtherCorporateIsRefused(): void
    {
        $this->assertCorporateRefusal($this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7']));
    }

    public function testCorporateMissingOrUndecodableTokenIsRefused(): void
    {
        $this->assertCorporateRefusal([]);
        $this->assertCorporateRefusal(['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'not-a-jwt']);
        $this->assertCorporateRefusal(['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'a.!!!.c']);
        $this->assertCorporateRefusal(['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'a.'.self::b64('"a string"').'.c']);
    }

    public function testCorporateRefusalLeavesNoOrphanUserRow(): void
    {
        $this->assertCorporateRefusal($this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7']), 'newcomer@example.com');
        self::assertNull($this->findUser('newcomer@example.com'));
    }

    public function testCorporateRefusalStillFlushesExistingSession(): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42');
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();

        $this->assertRefused('corporate', $this->get('/s/account', 'mallory@example.com', $this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7'])));
        self::assertNull($this->findUser('mallory@example.com'));
        $this->assertOldSessionIsGone($aliceSession);
    }

    public function testCorporateRevocationIsContinuous(): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42');
        $this->createUser('alice@example.com');
        $good = $this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42']);

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com', $good));
        $session = $this->sessionId();
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com', $good));
        self::assertSame($session, $this->sessionId(), 'matching session short-circuits');

        $this->assertRefused('corporate', $this->get('/s/keep-alive', 'alice@example.com', $this->token(['custom:is_corporate' => 'false'])));
    }

    // --- runtime flag (G9) and session TTL (G13c) ---------------------------------------------

    public function testInertWhenAuthTypeUnset(): void
    {
        $this->restartWithEnv('AUTH_TYPE', null);
        $count = $this->userCount();

        $this->assertAnonymous($this->get('/s/account', 'newcomer@example.com'));
        self::assertSame($count, $this->userCount());
    }

    public function testAuthTypeIsResolvedAtRuntime(): void
    {
        $compiled = glob(static::getContainer()->getParameter('kernel.cache_dir').'/*Container*.php') ?: [];
        self::assertNotEmpty($compiled);
        clearstatcache();
        $mtimes = array_map('filemtime', $compiled);

        $this->restartWithEnv('AUTH_TYPE', null);
        self::assertTrue(static::getContainer()->has(MpassProxyAuthenticator::class), 'registered while the flag is unset');
        $this->assertAnonymous($this->get('/s/account', 'runtime@example.com'));
        self::assertNull($this->findUser('runtime@example.com'));

        $this->restartWithEnv('AUTH_TYPE', 'SSO');
        $this->get('/s/account', 'runtime@example.com');
        self::assertNotNull($this->findUser('runtime@example.com'), 'same compiled container, flag flipped at runtime');

        clearstatcache();
        self::assertSame($mtimes, array_map('filemtime', $compiled), 'the container was not recompiled');
    }

    public function testDefaultRoleIsNotReadFromMauticConfig(): void
    {
        $roleId = $this->memberRole->getId();
        $this->configParams += ['sso_default_role' => $roleId, 'mpass_sso_default_role' => $roleId];
        $this->restartWithEnv('MPASS_SSO_DEFAULT_ROLE', null);

        $this->assertRefused('role', $this->get('/s/account', 'config@example.com'));
    }

    public function testIdleSessionIsInvalidatedAndReestablished(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
        $before = $this->sessionId();

        $ttl = (int) ini_get('session.gc_maxlifetime');
        $this->ageSession($before, $ttl + 60);

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
        self::assertNotSame($before, $this->sessionId(), 'the idle session was replaced');
        self::assertNotNull($this->reload($alice)->getLastLogin(), 're-established by Rule 3');
    }

    // --- helpers ------------------------------------------------------------------------------

    private static function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    /**
     * @param array<string, string> $claims
     *
     * @return array<string, string>
     */
    private function token(array $claims): array
    {
        return ['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => self::b64('{"alg":"none"}').'.'.self::b64((string) json_encode($claims)).'.sig'];
    }

    /**
     * @param array<string, string> $server
     */
    private function assertCorporateRefusal(array $server, string $email = 'alice@example.com'): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42');
        $count = $this->userCount();

        $this->assertRefused('corporate', $this->get('/s/account', $email, $server));
        self::assertSame($count, $this->userCount(), 'refused before find-or-create');
    }

    /** Rewrites the stored MetadataBag "last used" timestamp of a mock-file session. */
    private function ageSession(?string $id, int $seconds): void
    {
        $file = static::getContainer()->getParameter('kernel.cache_dir').'/sessions/'.$id.'.mocksess';
        self::assertFileExists($file);
        $data = unserialize((string) file_get_contents($file));
        $data['_sf2_meta']['u'] -= $seconds;
        $data['_sf2_meta']['c'] -= $seconds;
        file_put_contents($file, serialize($data));
    }
}
