<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional Eloquent observer that ends every session of an identity whose
 * password changed, ignoring the automatic rehash on sign-in.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeSessionsOnPasswordChange
{
    use RevokesOnceCommitted;

    /**
     * Handle the identity's update.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function updated(Model $model): void
    {
        if (!$model instanceof Identity || !$model->wasChanged($model->getAuthPasswordName())) {
            return;
        }

        Container::getInstance()->make(Rehashing::class)->unlessRehash($model, $model->getOriginal($model->getAuthPasswordName()), function () use ($model): void {
            $this->revokeOnceCommitted($model, static fn (SessionService $sessions): int => $sessions->passwordChanged($model));
        });
    }
}
