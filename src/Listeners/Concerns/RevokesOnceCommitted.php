<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners\Concerns;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * What the revoking listeners share: the default guard's session service,
 * resolved when the listener runs, and running the revocation only once the
 * change that caused it is committed on the changed model's connection, so a
 * change that is rolled back revokes nothing.
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
     */
    public function __construct(

        /** Container the session service and the transactions manager are resolved from. */
        private readonly Container $container,
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
     * The default guard's session service. Revocation covers every guard; the
     * default guard is the one that acts and whose request is reported.
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

        return $auth->sessions();
    }
}
