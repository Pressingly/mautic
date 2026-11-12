<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Security\Mpass;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\LockInterface;
use Symfony\Component\Lock\Store\FlockStore;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * The signing keys an mPass token issuer publishes at <issuer>/.well-known/jwks.json.
 *
 * PHP keeps nothing between requests, so the key set and the failure backoff live in a persistent
 * cache pool: without it every admin request (keep-alive XHRs included) would fetch the JWKS. A
 * flock() per issuer keeps concurrent Apache workers to one fetch at a time; the kernel drops it
 * when the worker exits, so a fatal error mid-fetch cannot leave it held.
 *
 * After a failed refresh the last good set keeps serving for STALE_GRACE_SECONDS past its
 * lifespan, so an issuer outage does not sign everyone out.
 */
final readonly class MpassJwks
{
    public const FETCH_TIMEOUT_SECONDS    = 2;
    public const LIFESPAN_SECONDS         = 3600;
    public const STALE_GRACE_SECONDS      = 86400;
    public const FAILURE_BACKOFF_SECONDS  = 30;
    public const REFRESH_INTERVAL_SECONDS = 30;
    public const LOCK_WAIT_SECONDS        = 3;
    private const LOCK_POLL_MICROSECONDS  = 100_000;

    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheItemPoolInterface $cache,
        private LockFactory $locks = new LockFactory(new FlockStore()),
    ) {
    }

    public static function url(string $issuer): string
    {
        return rtrim($issuer, '/').'/.well-known/jwks.json';
    }

    /**
     * The issuer's RS256 keys by kid. A stale set, or a kid missing from a set older than
     * REFRESH_INTERVAL_SECONDS (key rotation), triggers a refresh.
     *
     * @return array<string, Key>
     *
     * @throws MpassTokenException jwks_unavailable
     */
    public function signingKeys(string $issuer, string $kid): array
    {
        $cached = $this->cached($issuer);
        if (null !== $cached && !self::needsRefresh($cached, $kid)) {
            return self::parse($cached['jwks']);
        }

        $lastGood = self::lastGood($cached);
        $jwks     = $this->refresh($issuer, null === $lastGood ? self::LOCK_WAIT_SECONDS : 0) ?? $lastGood;

        return null === $jwks ? throw new MpassTokenException(MpassTokenException::JWKS_UNAVAILABLE) : self::parse($jwks);
    }

    /**
     * @param array{fetched_at: int, jwks: array<string, mixed>} $cached
     */
    private static function needsRefresh(array $cached, string $kid): bool
    {
        $age = time() - $cached['fetched_at'];

        return $age >= self::LIFESPAN_SECONDS || ($age >= self::REFRESH_INTERVAL_SECONDS && !self::containsKid($cached['jwks'], $kid));
    }

    /**
     * @param array{fetched_at: int, jwks: array<string, mixed>}|null $cached
     *
     * @return array<string, mixed>|null
     */
    private static function lastGood(?array $cached): ?array
    {
        $withinGrace = null !== $cached && time() - $cached['fetched_at'] < self::LIFESPAN_SECONDS + self::STALE_GRACE_SECONDS;

        return $withinGrace ? $cached['jwks'] : null;
    }

    /**
     * A freshly fetched set, or null when none could be had now (backoff, failure, or another
     * worker holding the fetch lock past $lockWaitSeconds: no wait at all while a last good set
     * can be served instead).
     *
     * @return array<string, mixed>|null
     */
    private function refresh(string $issuer, int $lockWaitSeconds): ?array
    {
        if ($this->recentlyFailed($issuer)) {
            return null;
        }

        $lock = $this->locks->createLock('mpass_jwks.'.hash('sha256', $issuer), self::LOCK_WAIT_SECONDS + self::FETCH_TIMEOUT_SECONDS);
        if (!$this->acquireWithin($lock, $lockWaitSeconds)) {
            return null;
        }

        try {
            $fresh = $this->cached($issuer);
            if (null !== $fresh && time() - $fresh['fetched_at'] < self::REFRESH_INTERVAL_SECONDS) {
                return $fresh['jwks'];
            }

            return $this->fetch($issuer);
        } finally {
            $lock->release();
        }
    }

    private function acquireWithin(LockInterface $lock, int $seconds): bool
    {
        $deadline = microtime(true) + $seconds;
        while (!$lock->acquire()) {
            if (microtime(true) >= $deadline) {
                return false;
            }
            usleep(self::LOCK_POLL_MICROSECONDS);
        }

        return true;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetch(string $issuer): ?array
    {
        try {
            $jwks = $this->httpClient->request('GET', self::url($issuer), [
                'timeout'       => self::FETCH_TIMEOUT_SECONDS,
                'max_duration'  => self::FETCH_TIMEOUT_SECONDS,
                'max_redirects' => 0,
                'headers'       => ['Accept' => 'application/json'],
            ])->toArray();
            self::parse($jwks);
        } catch (HttpClientException|MpassTokenException) {
            $this->recordFailure($issuer);

            return null;
        }

        $item = $this->cache->getItem(self::cacheKey('jwks', $issuer));
        $this->cache->save($item->set(['fetched_at' => time(), 'jwks' => $jwks])->expiresAfter(self::LIFESPAN_SECONDS + self::STALE_GRACE_SECONDS));

        return $jwks;
    }

    /**
     * @return array{fetched_at: int, jwks: array<string, mixed>}|null
     */
    private function cached(string $issuer): ?array
    {
        $item  = $this->cache->getItem(self::cacheKey('jwks', $issuer));
        $value = $item->isHit() ? $item->get() : null;

        return is_array($value) && is_int($value['fetched_at'] ?? null) && is_array($value['jwks'] ?? null) ? $value : null;
    }

    private function recentlyFailed(string $issuer): bool
    {
        return $this->cache->getItem(self::cacheKey('failed', $issuer))->isHit();
    }

    private function recordFailure(string $issuer): void
    {
        $item = $this->cache->getItem(self::cacheKey('failed', $issuer));
        $this->cache->save($item->set(true)->expiresAfter(self::FAILURE_BACKOFF_SECONDS));
    }

    /**
     * The RS256 keys that import; any other key (no kid, kty other than RSA, missing or invalid
     * n/e) is skipped rather than failing the whole set.
     *
     * @param array<string, mixed> $jwks
     *
     * @return array<string, Key>
     */
    private static function parse(array $jwks): array
    {
        $keys = [];
        foreach (is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [] as $jwk) {
            $kid = is_array($jwk) && is_string($jwk['kid'] ?? null) ? $jwk['kid'] : '';
            $key = '' === $kid ? null : self::importKey($jwk);
            if (null !== $key) {
                $keys[$kid] = $key;
            }
        }

        return [] === $keys ? throw new MpassTokenException(MpassTokenException::JWKS_UNAVAILABLE) : $keys;
    }

    /**
     * An RSA key as an RS256 Key, or null for anything else. kty is checked first so an EC or oct
     * key is never handed to the parser with the RS256 algorithm forced on it.
     *
     * @param array<string, mixed> $jwk
     */
    private static function importKey(array $jwk): ?Key
    {
        if ('RSA' !== ($jwk['kty'] ?? null)) {
            return null;
        }
        try {
            $key = JWK::parseKey($jwk, MpassTokenVerifier::ALGORITHM);
        } catch (\UnexpectedValueException|\InvalidArgumentException|\DomainException) {
            return null;
        }

        return null !== $key && MpassTokenVerifier::ALGORITHM === $key->getAlgorithm() ? $key : null;
    }

    /**
     * @param array<string, mixed> $jwks
     */
    private static function containsKid(array $jwks, string $kid): bool
    {
        $keys = is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [];

        return in_array($kid, array_column($keys, 'kid'), true);
    }

    private static function cacheKey(string $kind, string $issuer): string
    {
        return 'mpass_'.$kind.'.'.hash('sha256', $issuer);
    }
}
