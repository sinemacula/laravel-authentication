<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Binds the guard to a session a flow wrote once the session's connection
 * commits, and never when it rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeferredBind
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard that is bound. */
        private GuardContext $context,

        /** Defers the bind until the session's writes commit. */
        private AfterCommit $afterCommit,
    ) {}

    /**
     * Bind the session once its writes commit, then run what follows, bound or
     * not.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \Closure(): void  $bind
     * @param  ?\Closure(): void  $then
     * @return void
     */
    public function run(EloquentSession&Model $record, Principal $principal, \Closure $bind, ?\Closure $then = null): void
    {
        $deferred = $this->afterCommit->defers($record);
        $request  = $this->context->request();

        $this->afterCommit->run($record, function () use ($record, $principal, $bind, $then, $deferred, $request): void {

            if (!$deferred || ($this->context->request() === $request && $this->isStillActive($record, $principal))) {
                $bind();
            }

            if ($then === null) {
                return;
            }

            $then();
        });
    }

    /**
     * Whether the committed session, read again, is still the one the flow
     * wrote and still active.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function isStillActive(EloquentSession&Model $record, Principal $principal): bool
    {
        $stored = SessionLookup::find($record->getSessionIdentifier());

        return SessionOwnership::isSameSession($record, $stored)
            && PrincipalReference::isRecordedOn($stored, $principal)
            && OwnedSession::actsIn($stored, $record->getTenantId())
            && OwnedSession::refusal($stored, $this->context->name(), CarbonImmutable::now()->startOfSecond()) === null;
    }
}
