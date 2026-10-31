<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Applications;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The package's application policy: each application is a guard, and its
 * `application` configuration applies over the package defaults in
 * `authentication.application`, with the guard's lifetimes.
 *
 * A key present in the guard's `application` block wins, `null` included;
 * otherwise the package value applies. Nothing falls back to a literal: a key
 * missing at both levels, a malformed value, or a key the policy does not know
 * fails closed with an `InvalidArgumentException` naming the guard and the key.
 * An empty `methods` list is valid and allows nothing, so every sign-in,
 * refresh and machine credential of the application is refused as
 * `method_not_allowed`; it is the package default, so each application lists
 * what it allows. The application settings are read on every call, so a change
 * to them applies at once; the lifetimes come from the guard's token service,
 * which the token service factory builds once and keeps. Every principal is
 * admitted: an application that keeps some out rebinds the policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardApplicationPolicy implements ApplicationPolicy
{
    /** @var list<string> Keys an `application` block may hold. */
    private const array KEYS = ['methods', 'require_verified_identifier'];

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
     * Whether the sign-in method or machine credential is one the guard's
     * `methods` lists; an empty list allows none.
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
     * Admit every principal, holding the identity only to the
     * verified-identifier requirement (`admitIdentifier()`): the package has no
     * rule about which principals may hold the guard's sessions, so an
     * application that has one rebinds the policy.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function admit(string $guard, Identity $identity, Principal $principal, ?string $identifierType): ?FailureReason
    {
        return $this->admitIdentifier($guard, $identity, $identifierType);
    }

    /**
     * For a guard that sets `require_verified_identifier` and a sign-in that
     * used an identifier of a type, refuse the identity as
     * `identifier_unverified` unless it reports that identifier verified (read
     * on the write connection); otherwise admit it (`null`). The identity must
     * implement `HasVerifiableIdentifiers` then; one that does not is a
     * misconfiguration (`LogicException`). `admit()` asks it too.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function admitIdentifier(string $guard, Identity $identity, ?string $identifierType): ?FailureReason
    {
        if (!$this->settings($guard)['require_verified_identifier'] || $identifierType === null) {
            return null;
        }

        $verifiable = IdentifierVerifier::verifiable($identity);

        return WriteConnection::during($verifiable, static fn (): bool => $verifiable->hasVerifiedIdentifier($identifierType)) ? null : FailureReason::IDENTIFIER_UNVERIFIED;
    }

    /**
     * The lifetimes of the guard's token service.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function lifetimes(string $guard): TokenLifetimes
    {
        return $this->tokens->forGuard($guard)->lifetimes();
    }

    /**
     * Validate every application setting of the guard, failing closed as any
     * check would, without deciding anything; `authentication:check` runs it.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(string $guard): void
    {
        $this->settings($guard);
    }

    /**
     * The names the guard's `methods` lists, validated as every check validates
     * them; `authentication:check` reads them.
     *
     * @param  string  $guard
     * @return list<non-empty-string>
     *
     * @throws \InvalidArgumentException
     */
    public function methods(string $guard): array
    {
        return $this->settings($guard)['methods'];
    }

    /**
     * Resolve and validate every application setting of the guard, so a
     * malformed one fails closed whichever check runs first.
     *
     * @param  string  $guard
     * @return array{methods: list<non-empty-string>, require_verified_identifier: bool}
     *
     * @throws \InvalidArgumentException
     */
    private function settings(string $guard): array
    {
        $overrides = $this->block($guard, $this->guardConfig($guard)['application'] ?? [], 'the guard\'s `application` overrides');
        $defaults  = $this->block($guard, $this->config->get('authentication.application'), '`authentication.application`');
        $settings  = $overrides + $defaults;

        foreach (self::KEYS as $key) {
            if (!array_key_exists($key, $settings)) {
                throw new \InvalidArgumentException(self::message($guard, $key, 'set'));
            }
        }

        if (!self::isMethodList($settings['methods'])) {
            throw new \InvalidArgumentException(self::message($guard, 'methods', 'a list of lower-case sign-in method names'));
        }

        if (!is_bool($settings['require_verified_identifier'])) {
            throw new \InvalidArgumentException(self::message($guard, 'require_verified_identifier', 'true or false'));
        }

        return [
            'methods'                     => $settings['methods'],
            'require_verified_identifier' => $settings['require_verified_identifier'],
        ];
    }

    /**
     * Validate an application block: an array whose keys the policy knows.
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
            throw new \InvalidArgumentException("Application configuration for guard [{$guard}]: {$name} must be an array.");
        }

        foreach (array_keys($block) as $key) {
            if (!in_array($key, self::KEYS, true)) {
                throw new \InvalidArgumentException("Application configuration for guard [{$guard}]: {$name} has an unknown key `{$key}`.");
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
     * Whether the value is a list, possibly empty, of names a sign-in method
     * can be registered under, so a name no method can have (a casing slip such
     * as `Password`) fails closed as misconfiguration rather than refusing
     * every sign-in as `method_not_allowed`.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true list<non-empty-string> $value
     */
    private static function isMethodList(mixed $value): bool
    {
        if (!is_array($value) || !array_is_list($value)) {
            return false;
        }

        foreach ($value as $name) {
            if (!is_string($name) || !SignInMethodManager::isValidName($name)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Build the message for an application key that is missing or malformed.
     *
     * @param  string  $guard
     * @param  string  $key
     * @param  string  $expected
     * @return string
     */
    private static function message(string $guard, string $key, string $expected): string
    {
        return "Application `{$key}` for guard [{$guard}] must be {$expected}:"
            . " set `authentication.application.{$key}` or the guard's `application.{$key}` override.";
    }
}
