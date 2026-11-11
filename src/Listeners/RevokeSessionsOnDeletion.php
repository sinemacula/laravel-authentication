<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional Eloquent observer that ends the sessions of a deleted identity or
 * principal, once the delete commits.
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
