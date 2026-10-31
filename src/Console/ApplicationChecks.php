<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

/**
 * The application checks of `authentication:check`: each guard is an
 * application, decided by the bound `ApplicationPolicy`.
 *
 * With the package's policy a guard's application settings are validated. A
 * policy of the application's own is asked whether it allows each name a `jwt`
 * guard could use, so an exception it throws is reported for the guard; what it
 * answers is its own to decide. A `jwt` guard whose package settings list
 * nothing but `api_key`, which a `jwt` guard never accepts, gets a warning, not
 * a problem: an application may allow nothing on purpose (it issues tokens
 * itself, in access-only mode, or its sign-ins are stopped), and its access
 * tokens already issued keep working until they expire. Any other name counts,
 * registered or not, since `SessionService::start()` signs in under a name the
 * application passes. A policy of the application's own, one that wraps the
 * package's included, gets no warning: the names it allows are not known to the
 * command. The checks read configuration only and open no database connection,
 * though a policy of the application's own may open one when it is asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationChecks
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Config\Repository  $config
     */
    public function __construct(

        /** Container the bound policy and the sign-in methods are resolved from. */
        private Container $container,

        /** Configuration the guards are read from. */
        private ConfigRepository $config,
    ) {}

    /**
     * Check a `jwt` guard's application: the package policy's settings, or
     * every answer of a policy of the application's own.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function validate(string $guard): void
    {
        $policy = $this->policy();

        if (!$policy instanceof GuardApplicationPolicy) {

            foreach ($this->names() as $name) {
                $policy->allowsMethod($guard, $name);
            }

            return;
        }

        $policy->validate($guard);
    }

    /**
     * Check an `api_key` guard's application: that the bound policy allows
     * `api_key`, without which every key the guard is presented is refused.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validateApiKey(string $guard): void
    {
        if (!$this->policy()->allowsMethod($guard, ApiKeyGuard::METHOD)) {
            $name    = ApiKeyGuard::METHOD;
            $message = "An api_key guard's application must allow `{$name}`, or every key it is presented is refused: "
                . "with the package's policy, list `{$name}` in the guard's `application.methods`.";

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * The warnings about the `jwt` guards among those checked whose package
     * application settings allow nothing, each prefixed with its guard.
     *
     * @param  list<string>  $guards
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function warnings(array $guards): array
    {
        $policy = $this->policy();

        if (!$policy instanceof GuardApplicationPolicy) {
            return [];
        }

        $warnings = [];

        foreach ($guards as $guard) {

            if ($this->config->get("auth.guards.{$guard}.driver") !== 'jwt' || !self::allowsNothing($policy, $guard)) {
                continue;
            }

            $warnings[] = "[{$guard}] Allows no sign-in method or machine credential: every sign-in, refresh, code and password reset request is refused as "
                . '`method_not_allowed` and every client credentials exchange as `unauthorized_client`. List the methods the application uses in '
                . 'the guard\'s `application.methods` (or `authentication.application.methods`).';
        }

        return $warnings;
    }

    /**
     * Whether the guard's `methods` lists nothing a `jwt` guard accepts, which
     * is everything but `api_key`; settings the policy cannot read allow
     * something here, since the guard's own check reports them.
     *
     * @param  \SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy  $policy
     * @param  string  $guard
     * @return bool
     */
    private static function allowsNothing(GuardApplicationPolicy $policy, string $guard): bool
    {
        try {
            return array_diff($policy->methods($guard), [ApiKeyGuard::METHOD]) === [];
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * The names a `jwt` guard could allow: every registered sign-in method and
     * `client_credentials`.
     *
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function names(): array
    {
        return [...$this->container->make(SignInMethodManager::class)->names(), ClientCredentialsExchange::METHOD];
    }

    /**
     * The bound application policy.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function policy(): ApplicationPolicy
    {
        return $this->container->make(ApplicationPolicy::class);
    }
}
