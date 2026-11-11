<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Applications;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The default application policy: each guard is an application whose
 * `application` block applies over `authentication.application`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardApplicationPolicy implements ApplicationPolicy
{
    /** @var list<string> Keys an `application` block may hold. */
    private const array KEYS = ['methods', 'require_verified_identifier', 'client_secret_post'];

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
     * Whether the guard's `client_secret_post` is set, letting a client
     * credentials exchange read the client from the request body.
     *
     * @param  string  $guard
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function allowsClientSecretPost(string $guard): bool
    {
        return $this->settings($guard)['client_secret_post'];
    }

    /**
     * Refuse an unverified identifier when the guard sets
     * `require_verified_identifier`, otherwise admit it (`null`).
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
     * Validate every application setting of the guard.
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
     * The validated names the guard's `methods` lists.
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
     * Resolve and validate every application setting of the guard.
     *
     * @param  string  $guard
     * @return array{methods: list<non-empty-string>, require_verified_identifier: bool, client_secret_post: bool}
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

        foreach (['require_verified_identifier', 'client_secret_post'] as $key) {
            if (!is_bool($settings[$key])) {
                throw new \InvalidArgumentException(self::message($guard, $key, 'true or false'));
            }
        }

        return [
            'methods'                     => $settings['methods'],
            'require_verified_identifier' => $settings['require_verified_identifier'],
            'client_secret_post'          => $settings['client_secret_post'],
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
     * Whether the value is a list, possibly empty, of valid sign-in method
     * names.
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
