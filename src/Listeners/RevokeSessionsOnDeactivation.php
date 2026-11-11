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
 * Optional Eloquent observer that ends the sessions of an identity or principal
 * an update deactivates, once the update commits.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeSessionsOnDeactivation
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
