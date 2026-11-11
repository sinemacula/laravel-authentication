<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Verification;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Routing\UrlGenerator;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;

/**
 * Signs and consumes the signed links that verify an identity's identifier.
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
     * @param  \Illuminate\Routing\UrlGenerator  $urls
     * @param  \Illuminate\Auth\AuthManager  $auth
     * @param  \Illuminate\Config\Repository  $config
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     * @param  \Illuminate\Contracts\Container\Container  $container
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

        /** Container the event dispatcher is resolved from when a link is refused. */
        private Container $container,
    ) {}

    /**
     * Sign a link to the named route that verifies the identity's current
     * identifier of the type for the guard.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $route
     * @param  array<string, mixed>  $parameters
     * @param  ?int  $ttlMinutes
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     */
    public function create(string $guard, Identity $identity, string $type, string $route, array $parameters = [], ?int $ttlMinutes = null): Secret
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

        return new Secret($link);
    }

    /**
     * Check a verification link and verify the identifier it proves.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\SignedLink  $signed
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function consume(#[\SensitiveParameter] SignedLink $signed, ClientContext $client): VerificationLinkOutcome
    {
        $request = $signed->toRequest();
        $link    = self::link($request);

        if ($link === null || !$this->urls->hasCorrectSignature($request)) {
            return $this->refuse(new EventContext(null, $client), FailureReason::INVALID_CREDENTIALS);
        }

        [$guard, $id, $type, $hash] = $link;

        $provider = $this->provider($guard);
        $context  = new EventContext($provider === null ? null : $guard, $client);

        if (!$this->urls->signatureHasNotExpired($request)) {
            return $this->refuse($context, FailureReason::LINK_EXPIRED);
        }

        $identity = $provider === null ? null : $this->identity($provider, $id);

        if ($identity === null) {
            return $this->refuse($context, FailureReason::INVALID_CREDENTIALS);
        }

        $identifier = $this->provenIdentifier($identity, $type, $hash);

        return $identifier === null
            ? $this->refuse(new EventContext($guard, $client, $identity), FailureReason::INVALID_CREDENTIALS)
            : self::verifierOutcome($this->verifier->verify($guard, $identity, $type, $identifier, $client));
    }

    /**
     * The guard, identity, identifier type and digest a well-formed link
     * carries, or `null`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?array{0: string, 1: string, 2: string, 3: string}
     */
    private static function link(Request $request): ?array
    {
        $guard    = $request->query('guard');
        $identity = $request->query('identity');
        $type     = $request->query('type');
        $hash     = $request->query('hash');

        if (!self::hasPurposeAndExpiry($request) || !is_string($guard) || !is_string($identity)) {
            return null;
        }

        return is_string($type) && is_string($hash) && IdentifierType::isValid($type) ? [$guard, $identity, $type, $hash] : null;
    }

    /**
     * Whether the request's query names the verification purpose and an expiry.
     *
     * Laravel treats a signed link with no expiry, or `0`, as never expiring.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    private static function hasPurposeAndExpiry(Request $request): bool
    {
        $expires = $request->query('expires');

        return $request->query('purpose') === self::PURPOSE && is_string($expires) && ctype_digit($expires) && !str_starts_with($expires, '0');
    }

    /**
     * The identity's current identifier of the type when the link's digest
     * matches it, otherwise `null`.
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
     * connection.
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
     * The identity provider of the guard a link names, when it is a configured
     * JWT guard, otherwise `null`.
     *
     * @param  string  $guard
     * @return ?string
     */
    private function provider(string $guard): ?string
    {
        $config = $this->config->get("auth.guards.{$guard}");

        return is_array($config) && ($config['driver'] ?? null) === 'jwt' && is_string($config['provider'] ?? null) ? $config['provider'] : null;
    }

    /**
     * The identity a link names, or `null` when it is missing or cannot verify
     * identifiers.
     *
     * @param  string  $provider
     * @param  string  $identifier
     * @return (\SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity)|null
     */
    private function identity(string $provider, string $identifier): (HasVerifiableIdentifiers&Identity)|null
    {
        $users    = $this->auth->createUserProvider($provider);
        $identity = $users instanceof UserProvider ? $users->retrieveById($identifier) : null;

        return $identity instanceof Identity && $identity instanceof HasVerifiableIdentifiers ? $identity : null;
    }

    /**
     * Report a refused link and answer it with the outcome the reason names.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refuse(EventContext $context, FailureReason $reason): VerificationLinkOutcome
    {
        $this->container->make(Dispatcher::class)->dispatch(new AuthenticationFailed($context, AuthenticationFlow::IDENTIFIER_VERIFICATION, $reason));

        return $reason === FailureReason::LINK_EXPIRED ? VerificationLinkOutcome::EXPIRED : VerificationLinkOutcome::INVALID;
    }

    /**
     * The outcome of an accepted link, as the verifier answered it.
     *
     * @param  \SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification  $verification
     * @return \SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome
     */
    private static function verifierOutcome(IdentifierVerification $verification): VerificationLinkOutcome
    {
        return match ($verification) {
            IdentifierVerification::VERIFIED         => VerificationLinkOutcome::VERIFIED,
            IdentifierVerification::ALREADY_VERIFIED => VerificationLinkOutcome::ALREADY_VERIFIED,
            IdentifierVerification::MISMATCH         => VerificationLinkOutcome::MISMATCH,
        };
    }

    /**
     * The SHA-256 digest of the identifier's canonical form, or `null` when the
     * type's normaliser rejects it.
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
     * The given or configured link lifetime, from 1 minute to a week.
     *
     * @param  ?int  $ttlMinutes
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function ttl(?int $ttlMinutes): int
    {
        $ttl = $ttlMinutes ?? IntegerSetting::parse($this->config->get('authentication.verification.link_ttl_minutes'));

        if ($ttl === null || $ttl < 1 || $ttl > self::MAX_TTL_MINUTES) {
            $message = 'The verification link lifetime, `authentication.verification.link_ttl_minutes` or the one given,'
                . ' must be an integer from 1 to ' . self::MAX_TTL_MINUTES . ' minutes.';

            throw new \InvalidArgumentException($message);
        }

        return $ttl;
    }
}
