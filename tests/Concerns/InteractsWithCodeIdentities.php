<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Facades\Auth;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\Integration\Fixtures\CodeMachineClient;
use Tests\Integration\Fixtures\UnverifiableCodeIdentity;

/**
 * Shared set-up for tests that send and check one-time codes through the
 * package's guards: the `code_identities` table and its identities, and guards
 * that allow the code sign-in methods over them, built on the session tests'
 * helpers.
 *
 * Guards: `mobile` and `kiosk` allow `phone_code` (and `password`) over
 * `CodeIdentity`; `web` allows only `password`; `machines` allows `phone_code`
 * over `CodeMachineClient`; `unverifiable` allows `phone_code` over identities
 * that cannot report verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithCodeIdentities
{
    use InteractsWithCodes, InteractsWithSessions;

    /** @var string The seeded identity's phone number, in E.164. */
    protected const string PHONE = '+447700900123';

    /** @var string A phone number no identity has. */
    protected const string UNKNOWN_PHONE = '+447700900999';

    /**
     * Create the `code_identities` table.
     *
     * @return void
     */
    protected static function createCodeIdentitiesTable(): void
    {
        Schema::create('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('phone')->nullable()->unique();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('email')->nullable()->unique();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->datetimes(0);
        });
    }

    /**
     * Drop the `code_identities` table.
     *
     * @return void
     */
    protected static function dropCodeIdentitiesTable(): void
    {
        Schema::dropIfExists('code_identities');
    }

    /**
     * Register the providers and guards, a sync queue for code delivery, a
     * cheap password hash and a timebox short enough not to slow the suite.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureCodeGuards(ConfigRepository $config): void
    {
        $config->set('auth.providers.code_identities', ['driver' => 'model', 'model' => CodeIdentity::class]);
        $config->set('auth.providers.code_machines', ['driver' => 'model', 'model' => CodeMachineClient::class]);
        $config->set('auth.providers.unverifiable', ['driver' => 'model', 'model' => UnverifiableCodeIdentity::class]);

        $config->set('auth.guards.mobile', ['driver' => 'jwt', 'provider' => 'code_identities', 'audience' => ['methods' => ['phone_code', 'password']]]);
        $config->set('auth.guards.kiosk', ['driver' => 'jwt', 'provider' => 'code_identities', 'audience' => ['methods' => ['phone_code']]]);
        $config->set('auth.guards.web', ['driver' => 'jwt', 'provider' => 'code_identities', 'audience' => ['methods' => ['password']]]);
        $config->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'code_machines', 'audience' => ['methods' => ['phone_code']]]);
        $config->set('auth.guards.unverifiable', ['driver' => 'jwt', 'provider' => 'unverifiable', 'audience' => ['methods' => ['phone_code']]]);

        $config->set('queue.default', 'sync');
        $config->set('queue.connections.sync', ['driver' => 'sync']);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with the phone number and email address, each
     * verified unless said otherwise.
     *
     * @param  ?string  $phone
     * @param  ?string  $email
     * @param  bool  $verified
     * @param  bool  $active
     * @return \Tests\Integration\Fixtures\CodeIdentity
     */
    protected static function seedCodeIdentity(?string $phone = self::PHONE, ?string $email = 'ada@example.test', bool $verified = true, bool $active = true): CodeIdentity
    {
        $verifiedAt = $verified ? '2026-01-01 00:00:00' : null;

        return CodeIdentity::query()->create([
            'phone'             => $phone,
            'phone_verified_at' => $phone === null ? null : $verifiedAt,
            'email'             => $email,
            'email_verified_at' => $email === null ? null : $verifiedAt,
            'is_active'         => $active,
        ]);
    }

    /**
     * Start a request from the test client and return the named guard's code
     * service, on a guard resolved afresh for that request.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     */
    protected function codeService(string $guard = 'mobile'): CodeService
    {
        $this->freshGuard($guard);

        return Auth::manager()->codes($guard);
    }

    /**
     * The attempts counted against the one code stored.
     *
     * @return int
     */
    protected static function storedAttempts(): int
    {
        $attempts = DB::table('one_time_codes')->value('attempts');

        self::assertIsNumeric($attempts);

        return (int) $attempts;
    }
}
