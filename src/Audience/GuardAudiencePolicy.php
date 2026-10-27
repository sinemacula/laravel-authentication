<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Audience;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The package's audience policy: each guard's `audience` configuration over the
 * package defaults in `authentication.audience`, and its lifetimes per
 * principal type.
 *
 * A key present in the guard's `audience` block wins, `null` included;
 * otherwise the package value applies. Nothing falls back to a literal: a key
 * missing at both levels, a malformed value, or a key the policy does not know
 * fails closed with an `InvalidArgumentException` naming the guard and the key.
 * Every setting is read and checked on every call, so a malformed one fails the
 * first use of the guard's policy, whichever check that is, and nothing is
 * cached past a change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardAudiencePolicy implements AudiencePolicy
{
    /** @var list<string> Keys an `audience` block may hold. */
    private const array KEYS = ['methods', 'principal_types', 'require_verified_identifier'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory  $tokens
     */
    public function __construct(

        /** Configuration holding the guards and the package defaults. */
        private ConfigRepository $config,

        /** Guard-scoped token services, which own each guard's lifetimes. */
        private JwtTokenServiceFactory $tokens,
    ) {}

    /**
     * Whether the sign-in method is one the guard's `methods` lists.
     *
     * @param  string  $guard
     * @param  string  $method
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function allowsMethod(string $guard, string $method): bool
    {
        return in_array($method, $this->settings($guard)['methods'], true);
    }

    /**
     * Admit the principal when the guard admits any principal type, or lists
     * the principal's type (see `PrincipalType`); otherwise refuse it as
     * `principal_ineligible`. A principal without a type is refused by a guard
     * that lists types.
     *
     * Then, for a guard that sets `require_verified_identifier` and a sign-in
     * that used an identifier of a type, refuse it as `identifier_unverified`
     * unless the identity reports that identifier verified (read on the write
     * connection). The identity must implement `HasVerifiableIdentifiers`
     * then; one that does not is a misconfiguration (`LogicException`).
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    #[\Override]
    public function admit(string $guard, Identity $identity, Principal $principal, ?string $identifierType): ?SignInFailureReason
    {
        $settings = $this->settings($guard);
        $types    = $settings['principal_types'];

        if ($types !== null && !in_array(PrincipalType::of($principal), $types, true)) {
            return SignInFailureReason::PRINCIPAL_INELIGIBLE;
        }

        if (!$settings['require_verified_identifier'] || $identifierType === null) {
            return null;
        }

        $verifiable = IdentifierVerifier::verifiable($identity);

        return WriteConnection::during($verifiable, static fn (): bool => $verifiable->hasVerifiedIdentifier($identifierType)) ? null : SignInFailureReason::IDENTIFIER_UNVERIFIED;
    }

    /**
     * The guard's lifetimes for the principal's type: its
     * `jwt.by_principal_type` entry for that type when it has one, otherwise
     * the guard's own.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    #[\Override]
    public function lifetimes(string $guard, Principal $principal): TokenLifetimes
    {
        return $this->tokens->forGuard($guard)->lifetimesFor($principal);
    }

    /**
     * Resolve and validate every audience setting of the guard, so a malformed
     * one fails closed whichever check runs first.
     *
     * @param  string  $guard
     * @return array{methods: non-empty-list<non-empty-string>, principal_types: ?non-empty-list<non-empty-string>, require_verified_identifier: bool}
     *
     * @throws \InvalidArgumentException
     */
    private function settings(string $guard): array
    {
        $overrides = $this->block($guard, $this->guardConfig($guard)['audience'] ?? [], 'the guard\'s `audience` overrides');
        $defaults  = $this->block($guard, $this->config->get('authentication.audience'), '`authentication.audience`');
        $settings  = $overrides + $defaults;

        foreach (self::KEYS as $key) {
            if (!array_key_exists($key, $settings)) {
                throw new \InvalidArgumentException(self::message($guard, $key, 'set'));
            }
        }

        if (!self::isNameList($settings['methods']) || !self::areMethodNames($settings['methods'])) {
            throw new \InvalidArgumentException(self::message($guard, 'methods', 'a non-empty list of lower-case sign-in method names'));
        }

        if ($settings['principal_types'] !== null && !self::isNameList($settings['principal_types'])) {
            throw new \InvalidArgumentException(self::message($guard, 'principal_types', 'null or a non-empty list of principal types'));
        }

        if (!is_bool($settings['require_verified_identifier'])) {
            throw new \InvalidArgumentException(self::message($guard, 'require_verified_identifier', 'true or false'));
        }

        return [
            'methods'                     => $settings['methods'],
            'principal_types'             => $settings['principal_types'],
            'require_verified_identifier' => $settings['require_verified_identifier'],
        ];
    }

    /**
     * Validate an audience block: an array whose keys the policy knows.
     *
     * @param  string  $guard
     * @param  mixed  $block
     * @param  string  $name
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function block(string $guard, mixed $block, string $name): array
    {
        if (!is_array($block)) {
            throw new \InvalidArgumentException("Audience configuration for guard [{$guard}]: {$name} must be an array.");
        }

        foreach (array_keys($block) as $key) {
            if (!in_array($key, self::KEYS, true)) {
                throw new \InvalidArgumentException("Audience configuration for guard [{$guard}]: {$name} has an unknown key `{$key}`.");
            }
        }

        return $block;
    }

    /**
     * Resolve the guard's configuration block.
     *
     * @param  string  $guard
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function guardConfig(string $guard): array
    {
        $config = $this->config->get("auth.guards.{$guard}");

        if (!is_array($config)) {
            throw new \InvalidArgumentException("Auth guard [{$guard}] is not configured.");
        }

        return $config;
    }

    /**
     * Whether the value is a non-empty list of non-empty strings.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-list<non-empty-string> $value
     */
    private static function isNameList(mixed $value): bool
    {
        if (!is_array($value) || $value === [] || !array_is_list($value)) {
            return false;
        }

        foreach ($value as $name) {
            if (!is_string($name) || $name === '') {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether every name is one a sign-in method can be registered under, so a
     * name no method can have (a casing slip such as `Password`) fails closed
     * as misconfiguration rather than refusing every sign-in as
     * `method_not_allowed`.
     *
     * @param  non-empty-list<non-empty-string>  $names
     * @return bool
     */
    private static function areMethodNames(array $names): bool
    {
        foreach ($names as $name) {
            if (!SignInMethodManager::isValidName($name)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Build the message for an audience key that is missing or malformed.
     *
     * @param  string  $guard
     * @param  string  $key
     * @param  string  $expected
     * @return string
     */
    private static function message(string $guard, string $key, string $expected): string
    {
        return "Audience `{$key}` for guard [{$guard}] must be {$expected}:"
            . " set `authentication.audience.{$key}` or the guard's `audience.{$key}` override.";
    }
}
