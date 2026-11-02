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
 * Binds the guard to a session a flow wrote (a sign-in, a refresh or a switch)
 * once the writes on the session's connection commit, through `AfterCommit`,
 * after whatever the flow scheduled there first to report the write: at once,
 * with no extra query, when that connection has no transaction open; otherwise
 * at the commit, and never when it rolls back. The flow's pair, with a cookie
 * application's refresh cookie, is handed back on its result at once for the
 * application to attach; the package queues no cookie, so a rolled-back flow
 * leaves nothing on the response but what the caller chose to send.
 *
 * A bind that waited for the commit binds only while the guard still serves the
 * request that asked for it (a request rebound meanwhile is another's), and
 * reads the session again on the write connection first, binding it only while
 * it is still that session (generation and owner), recording the principal and
 * the tenant it was written for, of this guard, unrevoked, active and not
 * ended: a session revoked, returned to pending or switched later in the same
 * transaction is never bound as it was (a switch binds the guard to its
 * destination itself).
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
     * Run the bind of the session, written for the principal, once its writes
     * commit, as the class describes, and then, bound or not, what follows it.
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
     * Whether the committed session is still the one the flow wrote, read again
     * on the write connection: the same row (generation and owner), recording
     * the principal and the tenant it was written for, of this guard,
     * unrevoked, active and not ended.
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
