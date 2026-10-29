<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional Eloquent observer for `CanBeActive` identity and principal models:
 * ends every session of an identity (`identity_deactivated`), or every session
 * acting as a principal (`principal_deactivated`), when an update turns it from
 * active to inactive, once the update is committed. Registering it is the
 * opt-in:
 *
 * `User::observe(RevokeDevicesOnDeactivation::class);`
 *
 * Activity is judged on a copy holding the attributes as they were before the
 * update and on the model as it is now, so it suits activity held in the
 * model's own attributes (`ProvidesActiveState`); activity derived from
 * anything else calls `identityDeactivated()` or `principalDeactivated()`
 * itself. A model that is both identity and principal (2D) is treated as the
 * identity. A tenant has no observer: devices record principals, not tenants,
 * so the application calls `tenantDeactivated()` with the tenant's principals;
 * registering this observer on any other model throws a `LogicException` when
 * it is deactivated. Deactivation already stops every token at once through the
 * live activity checks; revoking makes it outlast a reactivation and records
 * why.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeDevicesOnDeactivation
{
    use RevokesOnceCommitted;

    /**
     * Handle the model's update.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \LogicException
     */
    public function updated(Model $model): void
    {
        if (!$model instanceof CanBeActive || $model->isActive() || !self::wasActive($model)) {
            return;
        }

        if ($model instanceof Identity) {
            $this->revokeOnceCommitted($model, static fn (SessionService $sessions): int => $sessions->identityDeactivated($model));
        } elseif ($model instanceof Principal) {
            $this->revokeOnceCommitted($model, static fn (SessionService $sessions): int => $sessions->principalDeactivated($model));
        } else {
            $message = 'Model %s is neither an identity nor a principal, so deactivating it ends no sessions here.'
                . ' A tenant\'s deactivation calls tenantDeactivated() with its principals.';

            throw new \LogicException(sprintf($message, $model::class));
        }
    }

    /**
     * Whether the model was active before the update, judged on a copy holding
     * its original attributes.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\CanBeActive  $model
     * @return bool
     */
    private static function wasActive(CanBeActive&Model $model): bool
    {
        $before = clone $model;

        $before->setRawAttributes($model->getRawOriginal());

        return $before->isActive();
    }
}
