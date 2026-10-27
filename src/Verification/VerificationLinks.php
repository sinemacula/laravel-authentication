<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Verification;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;

/**
 * Verifies identifiers by signed link: `create()` signs a link to a route of
 * the application's for one identity, guard and identifier, and `consume()`
 * checks a request to that route and verifies the identifier.
 *
 * A link is bound to its purpose (`verify_identifier`), its guard, its
 * identity, the identifier type, and the identifier itself through a SHA-256
 * digest of its canonical form, so it stops working when the identifier changes
 * and can be used for nothing else. It expires after
 * `authentication.verification.link_ttl_minutes`. Consuming a link never signs
 * anyone in, and consuming it again reports the identifier already verified.
 * The application owns the route, the message and its delivery.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerificationLinks
{
    /** @var string The purpose a verification link is signed for. */
    public const string PURPOSE = 'verify_identifier';

    /** @var list<string> Query parameters the link sets, which the application's own may not use. */
    public const array RESERVED_PARAMETERS = ['guard', 'identity', 'type', 'purpose', 'hash', 'expires', 'signature'];

    /** @var int Longest link lifetime, in minutes (one week). */
    public const int MAX_TTL_MINUTES = 10080;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Routing\UrlGenerator  $urls
     * @param  \Illuminate\Auth\AuthManager  $auth
     * @param  \Illuminate\Config\Repository  $config
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     */
    public function __construct(

        /** Signs and checks the links. */
        private UrlGenerator $urls,

        /** Resolves each guard's identity provider. */
        private AuthManager $auth,

        /** Configuration holding the guards and the link lifetime. */
        private ConfigRepository $config,

        /** Records the verification a link proves. */
        private IdentifierVerifier $verifier,
    ) {}

    /**
     * Sign a link to the named route that verifies the identity's current
     * identifier of the type for the guard, read on the write connection as
     * `consume()` reads it. The route's own parameters are kept, and the link
     * expires after `$ttlMinutes`, or the configured lifetime. An identity that
     * cannot verify identifiers is a misconfiguration (`LogicException`), and
     * so is a route whose path takes a reserved name as a placeholder
     * (`InvalidArgumentException`): the link's fields must reach `consume()` in
     * its query string.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $route
     * @param  array<string, mixed>  $parameters
     * @param  ?int  $ttlMinutes
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function create(string $guard, Identity $identity, string $type, string $route, array $parameters = [], ?int $ttlMinutes = null): string
    {
        $this->guardConfig($guard);

        $verifiable = IdentifierVerifier::verifiable($identity);
        $identifier = self::currentIdentifier($verifiable, IdentifierType::assertValid($type));
        $hash       = $identifier === null ? null : $this->digest($type, $identifier);

        if ($hash === null) {
            throw new \InvalidArgumentException(sprintf('%s has no %s identifier that can be verified.', $identity::class, $type));
        }

        $reserved = array_intersect(array_keys($parameters), self::RESERVED_PARAMETERS);

        if ($reserved !== []) {
            throw new \InvalidArgumentException('Verification link parameters may not use the reserved names: ' . implode(', ', $reserved) . '.');
        }

        $link = $this->urls->temporarySignedRoute($route, CarbonImmutable::now()->addMinutes($this->ttl($ttlMinutes)), [
            ...$parameters,
            'guard'    => $guard,
            'identity' => $identity->getAuthIdentifier(),
            'type'     => $type,
            'purpose'  => self::PURPOSE,
            'hash'     => $hash,
        ]);

        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);

        $placeholders = array_diff(self::RESERVED_PARAMETERS, array_keys($query));

        if ($placeholders !== []) {
            throw new \InvalidArgumentException("Verification route [{$route}] may not use the reserved names as placeholders: " . implode(', ', $placeholders) . '.');
        }

        return $link;
    }

    /**
     * Check a request to a verification link and verify the identifier it
     * proves: `null` when the link is not a valid, unexpired verification link
     * for the identity's current identifier, otherwise the outcome of the
     * verification.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function consume(Request $request): ?IdentifierVerification
    {
        $link = self::link($request);

        if ($link === null) {
            return null;
        }

        [$guard, $type, $hash] = $link;

        $identity   = $this->identity($guard, $request->query('identity'));
        $identifier = $identity === null ? null : $this->provenIdentifier($identity, $type, $hash);

        return $identity === null || $identifier === null
            ? null
            : $this->verifier->verify($guard, $identity, $type, $identifier, ClientContext::fromRequest($request));
    }

    /**
     * The guard, identifier type and digest of a request that carries a validly
     * signed, unexpired verification link, or `null`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?array{0: string, 1: string, 2: string}
     */
    private static function link(Request $request): ?array
    {
        $guard = $request->query('guard');
        $type  = $request->query('type');
        $hash  = $request->query('hash');

        // @phpstan-ignore staticMethod.dynamicCall
        if (!$request->hasValidSignature() || $request->query('purpose') !== self::PURPOSE) {
            return null;
        }

        return is_string($guard) && is_string($type) && is_string($hash) && IdentifierType::isValid($type) ? [$guard, $type, $hash] : null;
    }

    /**
     * The identity's current identifier of the type, read on the write
     * connection, when the link's digest is its digest; otherwise `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $hash
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function provenIdentifier(HasVerifiableIdentifiers&Identity $identity, string $type, string $hash): ?string
    {
        $identifier = self::currentIdentifier($identity, $type);
        $digest     = $identifier === null ? null : $this->digest($type, $identifier);

        return $digest !== null && hash_equals($digest, $hash) ? $identifier : null;
    }

    /**
     * The identity's current identifier of the type, read on the write
     * connection, so a link is signed for, and checked against, the address the
     * primary holds.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?string
     */
    private static function currentIdentifier(HasVerifiableIdentifiers&Identity $identity, string $type): ?string
    {
        return WriteConnection::during($identity, static fn (): ?string => $identity->getIdentifierForVerification($type));
    }

    /**
     * The identity a link names, loaded through its guard's identity provider
     * on the write connection: `null` when the guard is not a JWT guard, the
     * provider does not return it, or it cannot verify identifiers.
     *
     * @param  string  $guard
     * @param  mixed  $identifier
     * @return (\SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity)|null
     */
    private function identity(string $guard, mixed $identifier): (HasVerifiableIdentifiers&Identity)|null
    {
        $config   = $this->config->get("auth.guards.{$guard}");
        $provider = is_array($config) && ($config['driver'] ?? null) === 'jwt' && is_string($config['provider'] ?? null)
            ? $this->auth->createUserProvider($config['provider'])
            : null;

        $identity = $provider instanceof UserProvider && is_string($identifier) ? $provider->retrieveById($identifier) : null;

        return $identity instanceof Identity && $identity instanceof HasVerifiableIdentifiers ? $identity : null;
    }

    /**
     * The digest a link carries for an identifier: SHA-256 of its canonical
     * form, or `null` when the type's normaliser rejects it.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function digest(string $type, #[\SensitiveParameter] string $identifier): ?string
    {
        $canonical = $this->verifier->canonical($type, $identifier);

        return $canonical === null ? null : hash('sha256', $canonical);
    }

    /**
     * Resolve the guard's configuration, which must be a JWT guard's.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function guardConfig(string $guard): void
    {
        $config = $this->config->get("auth.guards.{$guard}");

        if (!is_array($config) || ($config['driver'] ?? null) !== 'jwt') {
            throw new \InvalidArgumentException("Auth guard [{$guard}] is not a configured jwt guard.");
        }
    }

    /**
     * The link lifetime: the given one, or the configured one, each an integer
     * from 1 to a week.
     *
     * @param  ?int  $ttlMinutes
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function ttl(?int $ttlMinutes): int
    {
        $ttl = $ttlMinutes ?? $this->config->get('authentication.verification.link_ttl_minutes');
        $ttl = is_string($ttl) && (string) (int) $ttl === $ttl ? (int) $ttl : $ttl;

        if (!is_int($ttl) || $ttl < 1 || $ttl > self::MAX_TTL_MINUTES) {
            $message = 'The verification link lifetime, `authentication.verification.link_ttl_minutes` or the one given,'
                . ' must be an integer from 1 to ' . self::MAX_TTL_MINUTES . ' minutes.';

            throw new \InvalidArgumentException($message);
        }

        return $ttl;
    }
}
