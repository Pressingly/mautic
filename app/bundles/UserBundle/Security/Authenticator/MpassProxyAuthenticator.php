<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Authenticator;

use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Mautic\CoreBundle\Helper\EncryptionHelper;
use Mautic\UserBundle\Entity\Role;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Model\UserModel;
use Mautic\UserBundle\Security\Mpass\MpassRefusalException;
use Mautic\UserBundle\Security\Mpass\ProxyIdentity;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Twig\Environment;

/**
 * mPass header authenticator for the `main` firewall (Rules 1–3 of the proxy-auth contract).
 *
 * Registered unconditionally in app/config/security.php; inert unless AUTH_TYPE=SSO at runtime.
 *
 * Trust chain — any broken link turns X-Auth-Request-Email into an impersonation vector:
 *  1. the container publishes no port, so Traefik is the only way in;
 *  2. the mautic-secure router runs strip-auth-headers before mpass-auth;
 *  3. oauth2-proxy validates the session and re-injects the headers on every request.
 *
 * Contract: sso-rules-moneta openspec/specs/proxy-auth-middleware/spec.md;
 * design: openspec/changes/add-mautic-to-sso/design.md §2–§4.
 */
final class MpassProxyAuthenticator extends AbstractAuthenticator implements InteractiveAuthenticatorInterface
{
    /** Request attribute: expire REMEMBERME on this response (read by MpassLocalAuthGuard). */
    public const EXPIRE_REMEMBER_ME = '_mpass_expire_rememberme';

    public function __construct(
        private readonly ProxyIdentity $identity,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly ManagerRegistry $doctrine,
        private readonly UserModel $userModel,
        private readonly Environment $twig,
        private readonly LoggerInterface $logger,
        private readonly ?string $defaultRole,
    ) {
    }

    public function supports(Request $request): bool
    {
        if (!$this->identity->isSso()) {
            return false;
        }

        $this->expireIdleSession($request);

        $asserted = $this->identity->asserted($request);
        if ('' === $asserted) {
            return false; // Rule 1: absence is not a logout signal
        }

        $user = $this->tokenStorage->getToken()?->getUser();
        if ($user instanceof User) {
            $resolved = $this->identity->resolve($asserted);
            if (null !== $resolved
                && ProxyIdentity::normalise($user->getEmail()) === $resolved
                && $this->identity->corporateOk($request)) {
                return false; // Rule 1: match, and corporate binding still holds (continuous)
            }
        }

        return true;
    }

    public function authenticate(Request $request): Passport
    {
        // Rule 2 — flush FIRST, before any refusal can bail out.
        $this->flush($request);

        $email = $this->identity->resolve($this->identity->asserted($request));
        if (null === $email) {
            throw new MpassRefusalException(MpassRefusalException::UNRESOLVABLE);
        }
        if (!$this->identity->corporateOk($request)) {
            throw new MpassRefusalException(MpassRefusalException::CORPORATE);
        }

        $user = $this->findByEmail($email) ?? $this->provision($email);
        if (!$user->isPublished()) {
            throw new MpassRefusalException(MpassRefusalException::INACTIVE);
        }

        return new SelfValidatingPassport(new UserBadge($user->getUserIdentifier(), fn () => $user));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null; // continue the original request as the authenticated user
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $reason = $exception instanceof MpassRefusalException ? $exception->reason : 'error';
        $this->logger->warning('mPass SSO refused a request', ['reason' => $reason, 'exception' => $exception]);
        $request->attributes->set(self::EXPIRE_REMEMBER_ME, true);

        // A 403 page, never a redirect to /s/login: that would loop (design.md §3).
        return new Response($this->twig->render('@MauticUser/Security/mpass.html.twig', ['reason' => $reason]), Response::HTTP_FORBIDDEN);
    }

    public function isInteractive(): bool
    {
        return true;
    }

    private function flush(Request $request): void
    {
        if (null === $this->tokenStorage->getToken()) {
            return;
        }
        if ($request->hasSession()) {
            $request->getSession()->invalidate();
        }
        $this->tokenStorage->setToken(null);
        $request->attributes->set(self::EXPIRE_REMEMBER_ME, true);
    }

    /**
     * G13c: PHP's session GC is probabilistic, so a session idle for longer than the TTL is dropped
     * here. session.gc_maxlifetime is the adapter the image renders from SESSION_TTL_SECONDS.
     */
    private function expireIdleSession(Request $request): void
    {
        if (!$request->hasSession() || !$request->getSession()->isStarted()) {
            return;
        }
        $session  = $request->getSession();
        $lastUsed = $session->getMetadataBag()->getLastUsed();
        $ttl      = (int) ini_get('session.gc_maxlifetime');
        if ($ttl > 0 && $lastUsed > 0 && time() - $lastUsed > $ttl) {
            $session->invalidate();
            $this->tokenStorage->setToken(null);
        }
    }

    /**
     * Email only — never UserProvider (it matches `username OR email`, G2). No isPublished filter,
     * no result cache, and a strict PHP comparison because the column collation may be
     * accent-insensitive.
     */
    private function findByEmail(string $email): ?User
    {
        $users = $this->em()->createQueryBuilder()
            ->select('u')
            ->from(User::class, 'u')
            ->where('u.email = :email')
            ->setParameter('email', $email)
            ->getQuery()
            ->getResult();

        foreach ($users as $user) {
            if (ProxyIdentity::normalise($user->getEmail()) === $email) {
                return $user;
            }
        }

        return null;
    }

    private function provision(string $email): User
    {
        $role = $this->defaultRole();
        [$local, $domain] = explode('@', $email, 2);

        $user = new User();
        $user->setEmail($email);
        $user->setUsername($email);
        $user->setFirstName($local);
        $user->setLastName($domain);
        $user->setRole($role);
        $user->setIsPublished(true);
        $user->setPassword($this->userModel->checkNewPassword($user, EncryptionHelper::generateKey()));

        try {
            $this->userModel->saveEntity($user);
        } catch (UniqueConstraintViolationException $e) {
            $this->doctrine->resetManager(); // the EntityManager is closed after a failed flush

            return $this->findByEmail($email)
                // Still absent: another row's username (or an accent-folded email) holds the value.
                ?? throw new MpassRefusalException(MpassRefusalException::CONFLICT, $e);
        }

        return $user;
    }

    /**
     * MPASS_SSO_DEFAULT_ROLE holds the id of a least-privilege, non-admin, published role created
     * at deploy time. Checked every time a user is created; existing users are never re-roled.
     */
    private function defaultRole(): Role
    {
        $id   = trim((string) $this->defaultRole);
        $role = ctype_digit($id) ? $this->em()->find(Role::class, (int) $id) : null;

        if (!$role instanceof Role || $role->isAdmin() || !$role->isPublished()) {
            throw new MpassRefusalException(MpassRefusalException::ROLE);
        }

        return $role;
    }

    private function em(): EntityManagerInterface
    {
        $em = $this->doctrine->getManagerForClass(User::class);
        \assert($em instanceof EntityManagerInterface);

        return $em;
    }
}
