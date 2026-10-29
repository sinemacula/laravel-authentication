<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;

/**
 * A queued job that saves a fresh hash of an identity's password through
 * Eloquent, outside any credential attempt and without signing anything out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SavePasswordJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  int  $identityId
     * @param  string  $password
     */
    public function __construct(

        /** Key of the identity whose password is saved. */
        public int $identityId,

        /** The password to save a fresh hash of. */
        public string $password,
    ) {}

    /**
     * Save a fresh hash of the password.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    public function handle(Hasher $hasher): void
    {
        IntegrationIdentity::query()->findOrFail($this->identityId)->forceFill(['password' => $hasher->make($this->password)])->save();
    }
}
