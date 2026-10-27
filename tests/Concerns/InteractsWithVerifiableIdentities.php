<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use Tests\Integration\Fixtures\VerifiableIdentity;

/**
 * Shared helpers for test cases that verify identifiers of the
 * `VerifiableIdentity` fixture.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithVerifiableIdentities
{
    /**
     * Create the identities table on the given connection, or the default one.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected static function createVerifiableIdentitiesTable(?string $connection = null): void
    {
        Schema::connection($connection)->create('verifiable_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('phone')->nullable();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('password');
            $blueprint->datetimes(0);
        });
    }

    /**
     * Persist an identity with the given email address, unverified, and load it
     * again from the write connection as stored.
     *
     * @param  ?string  $email
     * @param  ?string  $phone
     * @return \Tests\Integration\Fixtures\VerifiableIdentity
     */
    protected static function seedVerifiableIdentity(?string $email = 'ben@example.com', ?string $phone = null): VerifiableIdentity
    {
        $identity = VerifiableIdentity::query()->create(['email' => $email, 'phone' => $phone, 'password' => 'unused']);

        $fresh = WriteConnection::query(VerifiableIdentity::query())->find($identity->getKey());

        assert($fresh instanceof VerifiableIdentity);

        return $fresh;
    }
}
