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
        $this->assertSame($before, $this->sessionId(), 'no new session id');
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->reload($alice)->getLastLogin(), 'no users write: authenticate() never ran');
    }

    public function testNoLogoutWhenHeaderAbsent(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', null));
        $this->assertSame($before, $this->sessionId());
    }

    public function testMatchIsCaseAndWhitespaceInsensitive(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', '  ALICE@Example.COM  '));
        $this->assertSame($before, $this->sessionId());
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->reload($alice)->getLastLogin());
    }

    public function testMismatchFlushesAndReauths(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->createUser('bob@example.com');
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();

        $this->assertServedAs('bob@example.com', $this->get('/s/account', 'bob@example.com'));
        $this->assertNotSame($aliceSession, $this->sessionId(), 'session id changed');
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

        $this->assertSame($before, $this->sessionId(), 'no flush on the public firewall');
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->findUser('bob@example.com')->getLastLogin(), 'no login on the public firewall');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', null));
    }

    // --- Rule 3 / provisioning -----------------------------------------------------------------

    public function testFirstSeenEmailIsProvisionedWithDefaultRoleAndNames(): void
    {
        $this->get('/s/account', 'newcomer@example.com');

        $user = $this->findUser('newcomer@example.com');
        $this->assertInstanceOf(\Mautic\UserBundle\Entity\User::class, $user);
        $this->assertSame('newcomer@example.com', $user->getUserIdentifier());
        $this->assertSame('newcomer', $user->getFirstName());
        $this->assertSame('-', $user->getLastName());
        $this->assertSame($this->memberRole->getId(), $user->getRole()->getId());
        $this->assertTrue($user->isPublished());
        $this->assertNotEmpty($user->getPassword());
        $this->assertInstanceOf(\DateTimeInterface::class, $user->getLastLogin(), 'InteractiveLoginEvent fired');
    }

    public function testNamesAreSetOnlyAtCreationSoProfileEditsStick(): void
    {
        $this->get('/s/account', 'newcomer@example.com');
        // The user edits their names in Account settings.
        $this->connection->executeStatement(
            'UPDATE '.MAUTIC_TABLE_PREFIX."users SET first_name = 'Edited', last_name = 'Name' WHERE email = 'newcomer@example.com'"
        );
        // A real login request starts with no loaded entities; the test kernel keeps them.
        self::getContainer()->get(\Doctrine\ORM\EntityManagerInterface::class)->clear();

        // Switching away and back re-runs authenticate() for the same identity.
        $this->createUser('bob@example.com');
        $this->assertServedAs('bob@example.com', $this->get('/s/account', 'bob@example.com'));
        $this->assertServedAs('newcomer@example.com', $this->get('/s/account', 'newcomer@example.com'));

        $this->assertSame(
            ['first_name' => 'Edited', 'last_name' => 'Name'],
            $this->connection->fetchAssociative('SELECT first_name, last_name FROM '.MAUTIC_TABLE_PREFIX."users WHERE email = 'newcomer@example.com'")
        );
    }

    public function testRolePermissionsApplyOnTheFirstRequest(): void
    {
        $role = $this->em->find(Role::class, $this->memberRole->getId());
        $this->assertInstanceOf(Role::class, $role);
        self::getContainer()->get(RoleModel::class)->setRolePermissions($role, ['user:users' => ['view']]);
        $this->em->persist($role);
        $this->em->flush();

        // The login request itself, not the next one that reloads the user from the session.
        $this->assertSame(Response::HTTP_OK, $this->get('/s/users', 'newcomer@example.com')->getStatusCode());
    }

    public function testMixedCaseHeaderResolvesExistingUser(): void
    {
        $this->createUser('Alice@Example.com');
        $count = $this->userCount();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'ALICE@example.COM'));
        $this->assertSame($count, $this->userCount());
    }

    public function testDisplayNameIsNeverTheSub(): void
    {
        $this->restartWithEnv('DEFAULT_EMAIL_DOMAIN', 'corp.example');
        $sub = '892ae5ac-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
        $this->get('/s/account', '1020010000019120', ['HTTP_X_AUTH_REQUEST_USER' => $sub]);

        $user = $this->findUser('1020010000019120@corp.example');
        $this->assertInstanceOf(\Mautic\UserBundle\Entity\User::class, $user);
        $this->assertSame('1020010000019120', $user->getFirstName());
        $this->assertSame('-', $user->getLastName());
        $this->assertNotInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser($sub));
    }

    public function testSqlWildcardsAreLiteral(): void
    {
        $victim = $this->createUser('victim@example.com');

        $this->get('/s/account', 'v%@example.com');

        $this->assertInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('v%@example.com'), 'a new user, not the victim');
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->reload($victim)->getLastLogin());
    }

    public function testUsernameEqualToHeaderEmailDoesNotImpersonate(): void
    {
        $x     = $this->createUser('x@example.com', username: 'bob@corp.com');
        $count = $this->userCount();

        $this->assertRefused('conflict', $this->get('/s/account', 'bob@corp.com'));
        $this->assertSame($count, $this->userCount());
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->reload($x)->getLastLogin(), 'X was not logged in');
    }

    public function testUniqueViolationFallsBackToRead(): void
    {
        // Simulates losing the INSERT race: the row appears between the lookup and the flush.
        $count = $this->userCount();
        $this->createUser('racer@example.com', username: 'racer@example.com', role: $this->memberRole);
        $table = MAUTIC_TABLE_PREFIX.'users';
        $this->connection->executeStatement("UPDATE {$table} SET email = 'RACER-PENDING' WHERE email = 'racer@example.com'");

        $listener = function () use ($table): void {
            $this->connection->executeStatement("UPDATE {$table} SET email = 'racer@example.com' WHERE email = 'RACER-PENDING'");
        };
        self::getContainer()->get(\Symfony\Component\EventDispatcher\EventDispatcherInterface::class)->addListener(\Mautic\UserBundle\UserEvents::USER_PRE_SAVE, $listener);

        $response = $this->get('/s/account', 'racer@example.com');

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame($count + 1, $this->userCount(), 'no duplicate row');
    }

    public function testUnresolvableIdentityFlushes(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();
        $count        = $this->userCount();

        $this->assertRefused('unresolvable', $this->get('/s/account', '1020010000019120')); // no DEFAULT_EMAIL_DOMAIN
        $this->assertSame($count, $this->userCount());
        $this->assertOldSessionIsGone($aliceSession);
    }

    public function testXAuthRequestUserIsNeverUsed(): void
    {
        $count = $this->userCount();

        $this->assertAnonymous($this->get('/s/account', '   ', ['HTTP_X_AUTH_REQUEST_USER' => '892ae5ac-1c2d-4e5f-8a9b-0c1d2e3f4a5b']));
        $this->assertSame($count, $this->userCount());
    }

    public function testDefaultRoleGuard(): void
    {
        $count = $this->userCount();
        $cases = [
            'unset, and no "mPass Member" role' => '',
            'missing'     => '999999',
            'admin'       => (string) $this->adminRole->getId(),
            'unpublished' => (string) $this->createRole('mPass unpublished', false, false)->getId(),
            'name'        => 'mPass test members',
        ];

        foreach ($cases as $case => $value) {
            $this->restartWithEnv('MPASS_SSO_DEFAULT_ROLE', $value);
            $this->assertRefused('role', $this->get('/s/account', "role-{$case}@example.com"), $case);
            $this->assertSame($count, $this->userCount(), $case);
        }
    }

    /**
     * Bundle-contract review: with MPASS_SSO_DEFAULT_ROLE unset, the role named "mPass Member" (the
     * one the image creates at boot) is the default, so first boot needs no id copied into env. It
     * must still be a published, non-admin role.
     */
    public function testUnsetDefaultRoleFallsBackToTheMemberRoleByName(): void
    {
        $member = $this->createRole(MpassProxyAuthenticator::MEMBER_ROLE, false);
        $this->restartWithEnv('MPASS_SSO_DEFAULT_ROLE', null);

        $this->assertServedAs('newcomer@example.com', $this->get('/s/account', 'newcomer@example.com'));
        $this->assertSame($member->getId(), $this->findUser('newcomer@example.com')->getRole()->getId());

        $this->em->find(Role::class, $member->getId())->setIsAdmin(true);
        $this->em->flush();
        $this->client->getCookieJar()->clear();
        $this->assertRefused('role', $this->get('/s/account', 'second@example.com'), 'an admin "mPass Member" is refused');
    }

    public function testExistingUserIsNeverReRoled(): void
    {
        $alice = $this->createUser('alice@example.com');

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
        $this->assertSame($this->adminRole->getId(), $this->reload($alice)->getRole()->getId());
    }

    // --- corporate-tenant binding (audit row 22) ----------------------------------------------

    public function testCorporateUnsetSkipsCheck(): void
    {
        // Only with the explicit opt-in (set by the test base, as the devkit sets it).
        $this->createUser('alice@example.com');
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
    }

    public function testCorporateUnsetWithoutOptInRefusesEveryone(): void
    {
        // Round-2 review: fail closed in the app too, not only in the entrypoint.
        $this->restartWithEnv('MPASS_ALLOW_ANY_TENANT', null);
        $alice = $this->createUser('alice@example.com');
        $count = $this->userCount();

        $this->assertRefused('corporate', $this->get('/s/account', 'alice@example.com'));
        $this->assertRefused('corporate', $this->get('/s/account', 'newcomer@example.com'));
        $this->assertSame($count, $this->userCount(), 'nobody provisioned');
        $this->assertNotInstanceOf(\DateTimeInterface::class, $this->reload($alice)->getLastLogin());

        $this->restartWithEnv('MPASS_ALLOW_ANY_TENANT', '0');
        $this->assertRefused('corporate', $this->get('/s/account', 'alice@example.com'), 'only "1" opts in');
    }

    public function testAllowAnyTenantDoesNotWeakenAConfiguredBinding(): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42'); // MPASS_ALLOW_ANY_TENANT=1 is still set
        $this->createUser('alice@example.com');

        $this->assertRefused('corporate', $this->get('/s/account', 'alice@example.com', $this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7'])));
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
        $this->assertCorporateRefusal(['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'a.'.$this->b64('"a string"').'.c']);
    }

    public function testCorporateRefusalLeavesNoOrphanUserRow(): void
    {
        $this->assertCorporateRefusal($this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7']), 'newcomer@example.com');
        $this->assertNotInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('newcomer@example.com'));
    }

    public function testCorporateRefusalStillFlushesExistingSession(): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42');
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $aliceSession = $this->sessionId();

        $this->assertRefused('corporate', $this->get('/s/account', 'mallory@example.com', $this->token(['custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7'])));
        $this->assertNotInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('mallory@example.com'));
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
        $this->assertSame($session, $this->sessionId(), 'matching session short-circuits');

        $this->assertRefused('corporate', $this->get('/s/keep-alive', 'alice@example.com', $this->token(['custom:is_corporate' => 'false'])));
    }

    // --- runtime flag (G9) and session TTL (G13c) ---------------------------------------------

    public function testInertWhenAuthTypeUnset(): void
    {
        $this->restartWithEnv('AUTH_TYPE', null);
        $count = $this->userCount();

        $this->assertAnonymous($this->get('/s/account', 'newcomer@example.com'));
        $this->assertSame($count, $this->userCount());
    }

    public function testAuthTypeIsResolvedAtRuntime(): void
    {
        $compiled = glob(self::getContainer()->getParameter('kernel.cache_dir').'/*Container*.php') ?: [];
        $this->assertNotEmpty($compiled);
        clearstatcache();
        $mtimes = array_map(filemtime(...), $compiled);

        $this->restartWithEnv('AUTH_TYPE', null);
        $this->assertTrue(self::getContainer()->has(MpassProxyAuthenticator::class), 'registered while the flag is unset');
        $this->assertAnonymous($this->get('/s/account', 'runtime@example.com'));
        $this->assertNotInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('runtime@example.com'));

        $this->restartWithEnv('AUTH_TYPE', 'SSO');
        $this->get('/s/account', 'runtime@example.com');
        $this->assertInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('runtime@example.com'), 'same compiled container, flag flipped at runtime');

        clearstatcache();
        $this->assertSame($mtimes, array_map(filemtime(...), $compiled), 'the container was not recompiled');
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
        $this->assertNotSame($before, $this->sessionId(), 'the idle session was replaced');
        $this->assertInstanceOf(\DateTimeInterface::class, $this->reload($alice)->getLastLogin(), 're-established by Rule 3');
    }

    // --- edge secret (review finding 2a) -------------------------------------------------------

    public function testAdminUiWithoutOrWithWrongEdgeSecretIs403(): void
    {
        $count = $this->userCount();

        // A container on the shared network, or Mautic's own outbound HTTP, can reach Apache
        // directly with any header. On the admin UI that is refused outright (round-2 R2-5)...
        foreach (['', 'wrong-'.self::EDGE_SECRET] as $secret) {
            foreach (['/s/account', '/s/dashboard', '/s/keep-alive', '/%73/account'] as $path) {
                $response = $this->get($path, 'forged@example.com', ['HTTP_X_MPASS_EDGE_SECRET' => $secret]);
                $this->assertSame(403, $response->getStatusCode(), "{$path} with secret '{$secret}'");
            }
        }
        $this->assertSame($count, $this->userCount(), 'nobody provisioned');

        // ...an existing session is neither served nor flushed by such a request...
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();
        $this->assertSame(403, $this->get('/s/account', 'mallory@example.com', ['HTTP_X_MPASS_EDGE_SECRET' => 'wrong'])->getStatusCode());
        $this->assertSame($before, $this->sessionId());
        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));
    }

    public function testBypassPathWithoutEdgeSecretIsServedAndTrustsNoIdentity(): void
    {
        $count = $this->userCount();

        $this->assertSame(200, $this->get('/mtracking.gif', 'forged@example.com', ['HTTP_X_MPASS_EDGE_SECRET' => ''])->getStatusCode());
        $this->assertSame($count, $this->userCount());
    }

    /**
     * Bundle-contract review: the edge secret is opt-in. Unset, header trust is topology-based like
     * every other bundle app: the identity is honoured without any X-Mpass-Edge-Secret.
     */
    public function testUnsetEdgeSecretMeansTopologyTrust(): void
    {
        $this->restartWithEnv('MPASS_EDGE_SECRET', null);
        $this->createUser('alice@example.com');

        $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com', ['HTTP_X_MPASS_EDGE_SECRET' => '']));
    }

    public function testShortEdgeSecretTrustsNothing(): void
    {
        $this->restartWithEnv('MPASS_EDGE_SECRET', 'short');
        $this->assertSame(403, $this->get('/s/account', 'forged@example.com', ['HTTP_X_MPASS_EDGE_SECRET' => 'short'])->getStatusCode());
        $this->assertNotInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('forged@example.com'));
    }

    // --- review finding 15 ---------------------------------------------------------------------

    public function testWhitespaceOnlyHeaderKeepsTheSession(): void
    {
        $alice = $this->createUser('alice@example.com');
        $this->loginUser($alice);
        $before = $this->sessionId();

        $this->assertServedAs('alice@example.com', $this->get('/s/account', " \t "));
        $this->assertSame($before, $this->sessionId());
    }

    public function testNewEmailOnTheTrackingPixelCreatesNoUser(): void
    {
        $count = $this->userCount();

        $this->assertSame(Response::HTTP_OK, $this->get('/mtracking.gif', 'pixel@example.com')->getStatusCode());
        $this->assertSame($count, $this->userCount());
        $this->assertNotInstanceOf(\Mautic\UserBundle\Entity\User::class, $this->findUser('pixel@example.com'));
    }

    // --- review finding 8 ----------------------------------------------------------------------

    public function testMismatchDropsAnAnonymousSessionLeftBehind(): void
    {
        $this->createUser('bob@example.com');
        // An anonymous session with attributes a previous visitor left (no security token in it).
        $previous = self::getContainer()->get('session.factory')->createSession(); // @phpstan-ignore mautic.noContainerGet (no class-id alias)
        $previous->start();
        $previous->set('mpass_previous_visitor', 'alice-state');
        $previous->save();
        $this->client->getCookieJar()->set(new \Symfony\Component\BrowserKit\Cookie($this->sessionName(), $previous->getId()));

        $this->assertServedAs('bob@example.com', $this->get('/s/account', 'bob@example.com'));

        $this->assertNotSame($previous->getId(), $this->sessionId(), 'a new session id');
        $file = self::getContainer()->getParameter('kernel.cache_dir').'/sessions/'.$this->sessionId().'.mocksess';
        $this->assertFileExists($file);
        $this->assertStringNotContainsString('alice-state', (string) file_get_contents($file), 'bob did not inherit it');
    }

    // --- helpers ------------------------------------------------------------------------------

    private function b64(string $s): string
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
        return ['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => $this->b64('{"alg":"none"}').'.'.$this->b64((string) json_encode($claims)).'.sig'];
    }

    /**
     * @param array<string, string> $server
     */
    private function assertCorporateRefusal(array $server, string $email = 'alice@example.com'): void
    {
        $this->restartWithEnv('SMB_CORPORATE_ID', 'acme-42');
        $count = $this->userCount();

        $this->assertRefused('corporate', $this->get('/s/account', $email, $server));
        $this->assertSame($count, $this->userCount(), 'refused before find-or-create');
    }

    /** Rewrites the stored MetadataBag "last used" timestamp of a mock-file session. */
    private function ageSession(?string $id, int $seconds): void
    {
        $file = self::getContainer()->getParameter('kernel.cache_dir').'/sessions/'.$id.'.mocksess';
        $this->assertFileExists($file);
        $data = unserialize((string) file_get_contents($file), ['allowed_classes' => true]); // the test's own session file; it holds the security token
        $data['_sf2_meta']['u'] -= $seconds;
        $data['_sf2_meta']['c'] -= $seconds;
        file_put_contents($file, serialize($data));
    }
}
