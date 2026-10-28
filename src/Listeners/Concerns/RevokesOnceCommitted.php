<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners\Concerns;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * What the revoking listeners share: a jwt guard's session service, resolved
 * when the listener runs, and running the revocation only once the change that
 * caused it is committed on the changed model's connection, so a change that is
 * rolled back revokes nothing.
 *
 * Revocation covers every guard; the guard only names the acting guard and the
 * request in the events. It is the guard given to the listener (a contextual
 * binding of `$guard`), else the current default guard when that is a jwt
 * guard, else the first jwt guard configured, so a route guarded by another
 * driver (which makes that driver's guard the default through `shouldUse()`)
 * still revokes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RevokesOnceCommitted
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  ?string  $guard
     */
    public function __construct(

        /** Container the session service and the transactions manager are resolved from. */
        private readonly Container $container,

        /** Name of the jwt guard whose session service acts, or `null` to find one when the listener runs. */
        private readonly ?string $guard = null,
    ) {}

    /**
     * Run the revocation once the change to the model is committed: at once
     * when its connection has no open transaction, when that transaction
     * commits otherwise, and never when it is rolled back. A subject that is
     * not an Eloquent model has no transaction to wait for.
     *
     * @param  object  $subject
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService): mixed  $revoke
     * @return void
     */
    private function revokeOnceCommitted(object $subject, \Closure $revoke): void
    {
        $run = function () use ($revoke): void {
            $revoke($this->sessions());
        };

        if (!$subject instanceof Model) {
            $run();

            return;
        }

        $container = $this->container;

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))->run($subject, $run);
    }

    /**
     * The acting guard's session service.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function sessions(): SessionService
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth = $this->container->make('auth');

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->container->make('config');
        $guards = $config->get('auth.guards');

        return $auth->sessions($this->guard ?? self::jwtGuardName($auth->getDefaultDriver(), is_array($guards) ? $guards : []));
    }

    /**
     * The default guard when it is a jwt guard, else the first jwt guard
     * configured.
     *
     * @param  string  $default
     * @param  array<array-key, mixed>  $guards
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function jwtGuardName(string $default, array $guards): string
    {
        if (self::isJwtGuard($guards[$default] ?? null)) {
            return $default;
        }

        foreach ($guards as $name => $guard) {

            if (self::isJwtGuard($guard)) {
                return (string) $name;
            }
        }

        throw new \InvalidArgumentException('No jwt guard is configured, so no session service can revoke the sessions.');
    }

    /**
     * Whether the guard configuration is a jwt guard's.
     *
     * @param  mixed  $guard
     * @return bool
     */
    private static function isJwtGuard(mixed $guard): bool
    {
        return is_array($guard) && ($guard['driver'] ?? null) === 'jwt';
    }
}
