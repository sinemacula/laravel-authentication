<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;

/**
 * Queued job whose `web` guard `attemptWhen()` throws from its callback after
 * validating, leaving the validated user marked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AbandonedAttemptJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  array<string, string>  $credentials
     */
    public function __construct(

        /** The credentials the attempt is made with. */
        public array $credentials,
    ) {}

    /**
     * Make the attempt and swallow its callback's exception.
     *
     * @return void
     */
    public function handle(): void
    {
        $guard = Auth::guard('web');

        try {
            $guard->attemptWhen($this->credentials, static function (): never {
                throw new \RuntimeException('callback failed');
            });
        } catch (\RuntimeException) { // @phpstan-ignore catch.neverThrown
            app()->instance('abandoned.attempt', true);
            app()->instance('abandoned.mark', app(Rehashing::class));
        }
    }
}
