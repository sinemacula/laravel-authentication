<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Passwords\NotifyingResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordSettings;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The password checks of `authentication:check`: the policy settings, each of
 * which otherwise fails only when a password is first checked, and warnings,
 * not problems, about each `jwt` guard checked whose password resets would
 * refuse to run, since the reset helpers are optional. A guard is warned about
 * when its provider's model lives on another connection than the device model
 * (see `SharedConnection`; identifier changes need the same), and when its
 * password identifier is not `email` while Laravel's notification is the reset
 * link sender. Settings the guard's own checks report are left to them.
 * Configuration is read only: no database connection is opened.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasswordChecks
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Config\Repository  $config
     */
    public function __construct(

        /** Container the bound reset link sender is resolved from. */
        private Container $container,

        /** Configuration the settings are read from. */
        private ConfigRepository $config,
    ) {}

    /**
     * The checks of the password policy settings: the lengths, the composition
     * rules, what an unavailable breached check does and the reset link
     * lifetime.
     *
     * @return list<\Closure(): mixed>
     */
    public function settings(): array
    {
        $config = $this->config;

        return [
            static function () use ($config): void {
                (new PasswordSettings($config))->validate();
            },
        ];
    }

    /**
     * The warnings about the `jwt` guards among those checked, each prefixed
     * with its guard.
     *
     * @param  list<string>  $guards
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function warnings(array $guards): array
    {
        $notifies = $this->container->make(PasswordResetLinkSender::class) instanceof NotifyingResetLinkSender;
        $warnings = [];

        foreach ($guards as $guard) {

            if ($this->config->get("auth.guards.{$guard}.driver") !== 'jwt') {
                continue;
            }

            $found = [$this->connectionWarning($guard), $notifies ? $this->senderWarning($guard) : null];

            foreach (array_filter($found, is_string(...)) as $warning) {
                $warnings[] = "[{$guard}] {$warning}";
            }
        }

        return $warnings;
    }

    /**
     * What keeps the guard's password resets and identifier changes from
     * running on its provider's model, or `null`.
     *
     * @param  string  $guard
     * @return ?string
     */
    private function connectionWarning(string $guard): ?string
    {
        try {
            $model    = SharedConnection::providerModel($guard, $this->config);
            $mismatch = $model === null ? null : SharedConnection::mismatch($model, $this->config);
        } catch (\RuntimeException) {
            return null;
        }

        return $mismatch === null ? null : 'Password resets and identifier changes spend their proof with their change to the identity in one transaction, so ' . $mismatch;
    }

    /**
     * What keeps Laravel's notification from delivering the guard's reset
     * links, or `null`: the guard identifies passwords by something other than
     * `email`.
     *
     * @param  string  $guard
     * @return ?string
     */
    private function senderWarning(string $guard): ?string
    {
        try {
            $type = (new PasswordSignIn($this->config))->identifierType($guard);
        } catch (\InvalidArgumentException) {
            return null;
        }

        if ($type === NotifyingResetLinkSender::IDENTIFIER_TYPE) {
            return null;
        }

        $message = 'Password reset links are refused: the guard identifies passwords by [%s], and the bound %s, Laravel\'s notification, can only link an email address.';

        return sprintf($message, $type, NotifyingResetLinkSender::class);
    }
}
