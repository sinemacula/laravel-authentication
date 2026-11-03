<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;

/**
 * What the request is authenticated as, as plain values a policy condition can
 * be judged on: built once per unchanged authentication state from what the
 * guard validated (the credential, the session and its proofs, the request the
 * trusted proxies resolved), never from input, and held by the guard, so it
 * lives as long as the request does, under Octane too.
 *
 * The package's own keys are under the reserved `authentication` namespace, one
 * per property (see `toArray()`); `mfa` is an accepted further factor, or an
 * external provider's evidence accepted for an additional verification or
 * multifactor authentication, never counted from `amr`. A contributor the
 * application or a sibling package registers adds keys under a namespace of its
 * own (`mfa` and `sso` are kept for those siblings), so no key can collide with
 * another's: `get('sso.connection_id')`.
 *
 * Holds no model and no secret, so it can be logged, compared or queued as it
 * is. Its constructor is public, so a test builds one; it refuses contributed
 * keys a contributor could not have given.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<string, mixed>>
 */
final readonly class AuthenticationContext implements Arrayable
{
    /** @var string The namespace of the package's own keys, which no contributor may take. */
    public const string NAMESPACE = 'authentication';

    /** @var array<string, array<string, mixed>> The keys contributors added, by namespace. */
    public array $contributed;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType  $subjectType
     * @param  string  $identityType
     * @param  ?string  $identityId
     * @param  string  $principalType
     * @param  ?string  $principalId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @param  string  $application
     * @param  ?string  $sessionId
     * @param  list<string>  $amr
     * @param  ?\Carbon\CarbonImmutable  $authTime
     * @param  bool  $mfa
     * @param  bool  $recoveryCode
     * @param  bool  $multifactor
     * @param  ?int  $secondsSinceStepUp
     * @param  ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind  $credential
     * @param  ?list<string>  $scopes
     * @param  ?string  $ip
     * @param  array<array-key, mixed>  $contributed
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Whether the identity is a person or a machine (a `MachineIdentity`). */
        public SubjectType $subjectType,

        /** The identity's morph class (an Eloquent model's morph class, or its class name). */
        public string $identityType,

        /** The identity's auth identifier; `null` only for one that has none to write (an unsaved model's). */
        public ?string $identityId,

        /** The principal's morph class; the identity's own in two-dimensional mode. */
        public string $principalType,

        /** The principal's identifier; `null` only for one that has none to write. */
        public ?string $principalId,

        /** The active tenant's morph class, `null` when the request acts in none. */
        public ?string $tenantType,

        /** The active tenant's identifier, `null` when the request acts in none. */
        public ?string $tenantId,

        /** The application: the guard's name, a token's `client_id`. */
        public string $application,

        /** The bound session's identifier, `null` without one. */
        public ?string $sessionId,

        /** The session's `amr` values, worked out from its proofs; empty without a session. */
        public array $amr,

        /** When the session's newest counting proof was made (`auth_time`), `null` without a session. */
        public ?CarbonImmutable $authTime,

        /** Whether an accepted additional verification is on the session; never counted from `amr`. */
        public bool $mfa,

        /** Whether an accepted recovery code is on the session. */
        public bool $recoveryCode,

        /** Whether an accepted evaluation on the session reported multifactor authentication (`amr` then carries `mfa`). */
        public bool $multifactor,

        /** Seconds from the newest proof that set `mfa` or `recoveryCode` to when the context was built, `null` for none. */
        public ?int $secondsSinceStepUp,

        /** The kind of credential the request presented; `null` for a sign-in or a trusted bind made in the request. */
        public ?CredentialKind $credential,

        /** The scopes the credential grants; `null` for a person's session, which no credential limits. */
        public ?array $scopes,

        /** The client's IP address, as the request resolves it through the trusted proxies; `null` when it is not one. */
        public ?string $ip,

        // The keys contributors added, by namespace, kept only once checked.
        array $contributed = [],
    ) {
        $this->contributed = self::checked($contributed);
    }

    /**
     * Whether the context holds the key, `namespace.key`, even with a `null`
     * value.
     *
     * @param  string  $key
     * @return bool
     */
    public function has(string $key): bool
    {
        [$namespace, $name] = self::split($key);

        return $name !== null && array_key_exists($name, $this->keysOf($namespace));
    }

    /**
     * The value of the key, `namespace.key` (`authentication.mfa`,
     * `sso.connection_id`), or the default when the context does not hold it; a
     * key held with a `null` value gives `null`.
     *
     * @param  string  $key
     * @param  mixed  $default
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        [$namespace, $name] = self::split($key);

        $keys = $this->keysOf($namespace);

        return $name !== null && array_key_exists($name, $keys) ? $keys[$name] : $default;
    }

    /**
     * Every key as plain values, by namespace: the package's under
     * `authentication`, with the enums as their values and `auth_time` as Unix
     * seconds, then each contributor's.
     *
     * @return array<string, array<string, mixed>>
     */
    #[\Override]
    public function toArray(): array
    {
        return [self::NAMESPACE => $this->ownKeys(), ...$this->contributed];
    }

    /**
     * The package's own keys.
     *
     * @return array<string, mixed>
     */
    private function ownKeys(): array
    {
        return [
            'subject_type'          => $this->subjectType->value,
            'identity_type'         => $this->identityType,
            'identity_id'           => $this->identityId,
            'principal_type'        => $this->principalType,
            'principal_id'          => $this->principalId,
            'tenant_type'           => $this->tenantType,
            'tenant_id'             => $this->tenantId,
            'application'           => $this->application,
            'session_id'            => $this->sessionId,
            'amr'                   => $this->amr,
            'auth_time'             => $this->authTime?->getTimestamp(),
            'mfa'                   => $this->mfa,
            'recovery_code'         => $this->recoveryCode,
            'multifactor'           => $this->multifactor,
            'seconds_since_step_up' => $this->secondsSinceStepUp,
            'credential'            => $this->credential?->value,
            'scopes'                => $this->scopes,
            'ip'                    => $this->ip,
        ];
    }

    /**
     * The keys of a namespace, empty for one the context does not hold.
     *
     * @param  string  $namespace
     * @return array<string, mixed>
     */
    private function keysOf(string $namespace): array
    {
        return $namespace === self::NAMESPACE ? $this->ownKeys() : ($this->contributed[$namespace] ?? []);
    }

    /**
     * The contributed keys, once every namespace is one a contributor may have
     * and every key and value one it may give.
     *
     * @param  array<array-key, mixed>  $contributed
     * @return array<string, array<string, mixed>>
     *
     * @throws \InvalidArgumentException
     */
    private static function checked(array $contributed): array
    {
        $checked = [];

        foreach ($contributed as $namespace => $keys) {

            if (!is_string($namespace) || !ContextKeys::isNamespace($namespace)) {
                $message = 'The contributed namespace [%s] is the package\'s own, or is not a lower-case letter'
                    . ' and then up to 31 lower-case letters, digits or underscores.';

                throw new \InvalidArgumentException(sprintf($message, $namespace));
            }

            $keys = ContextKeys::checked($namespace, $keys);

            if (is_string($keys)) {
                throw new \InvalidArgumentException($keys);
            }

            $checked[$namespace] = $keys;
        }

        return $checked;
    }

    /**
     * The namespace and the key's name, the name `null` unless the key holds
     * exactly one dot.
     *
     * @param  string  $key
     * @return array{0: string, 1: ?string}
     */
    private static function split(string $key): array
    {
        $parts = explode('.', $key);

        return count($parts) === 2 ? [$parts[0], $parts[1]] : [$key, null];
    }
}
