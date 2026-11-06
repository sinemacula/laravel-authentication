<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional Eloquent observer for identity and principal models: ends every
 * session of an identity (`identity_deleted`), or every session acting as a
 * principal (`principal_deleted`), when it is deleted, once the delete is
 * committed on the model's connection, so a delete that is rolled back revokes
 * nothing. Registering it is the opt-in:
 *
 * `User::observe(RevokeSessionsOnDeletion::class);`
 *
 * A soft delete counts as deletion. A restore brings no session back, and a
 * later force delete runs again and revokes only a session written since,
 * normally none. A model that is both identity and principal (2D) is treated as
 * the identity. Only a delete through a model instance fires the event, so a
 * query delete, `deleteQuietly()`, `forceDeleteQuietly()`, `withoutEvents()`
 * and a database cascade end nothing here: a principal a cascade removes with
 * its identity is covered by the identity's own revocation, which ends every
 * session the identity holds. Registering this observer on any other model
 * throws a `LogicException` when it is deleted. Deletion already stops every
 * token while the deleted model no longer resolves; revoking records why, ends
 * the sessions in listings and makes the end outlast a restore. A sign-in, a
 * choice of principal or a switch that admitted the model before the delete
 * committed, and wrote its session after this revocation read the sessions,
 * ends that session itself once it checks it (`AdmissionRecheck`), so no
 * session survives the restore, unless the restore came before that check: then
 * only a "tokens valid after" cutoff (`HasTokensValidAfter`) this revocation
 * moved after the call began ends it (see `SessionRevocations`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeSessionsOnDeletion
{
    use RevokesOnceCommitted;

    /**
     * Handle the model's deletion.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \LogicException
     */
    public function deleted(Model $model): void
    {
        if ($model instanceof Identity) {
            $this->revokeOnceCommitted($model, static fn (SessionService $sessions): int => $sessions->identityDeleted($model));
        } elseif ($model instanceof Principal) {
            $this->revokeOnceCommitted($model, static fn (SessionService $sessions): int => $sessions->principalDeleted($model));
        } else {
            $message = 'Model %s is neither an identity nor a principal, so deleting it ends no sessions here.'
                . ' A tenant\'s sessions end through tenantDeactivated() with its principals.';

            throw new \LogicException(sprintf($message, $model::class));
        }
    }
}
