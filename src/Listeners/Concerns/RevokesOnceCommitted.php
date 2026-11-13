<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Resolves a jwt guard's session service and runs a revocation only once the
 * change that caused it commits.
 *
 * Services come from the container serving now: under Octane the listener's own
 * container is the booted application, not the request's sandbox.
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
     * @param  ?string  $guard
     */
    public function __construct(

        /** Name of the jwt guard whose session service acts, or `null` to find one when the listener runs. */
        private readonly ?string $guard = null,
    ) {}

    /**
     * Run the revocation once the change to the model commits, and never when
     * it is rolled back.
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

        $container = Container::getInstance();

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
        $auth = Container::getInstance()->make('auth');

        return $auth->sessions($this->guard);
    }
}
