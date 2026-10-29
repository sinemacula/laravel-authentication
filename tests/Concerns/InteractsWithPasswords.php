<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\Integration\Fixtures\PasswordMachine;

/**
 * Shared set-up for tests of the password helpers: the `password_identities`
 * table, identities seeded in it, and guards over them, built on the session
 * tests' helpers.
 *
 * Guards: `web` and `admin` allow `password` over `PasswordIdentity`, so a
 * password change or reset through one ends the sessions of both; `machines`
 * allows `password` over `PasswordMachine`; `console` also requires verified
 * identifiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithPasswords
{
    use InteractsWithSessions;

    /**
     * Create the `password_identities` table.
     *
     * @return void
     */
    protected static function createPasswordTables(): void
    {
        Schema::create('password_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable()->unique();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('phone')->nullable()->unique();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->string('nickname')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the `password_identities` table.
     *
     * @return void
     */
    protected static function dropPasswordTables(): void
    {
        Schema::dropIfExists('password_identities');
    }

    /**
     * Register the guards and providers, a cheap password hash, and a timebox
     * short enough not to slow the suite.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configurePasswordGuards(ConfigRepository $config): void
    {
        $audience = ['methods' => ['password']];

        $config->set('auth.providers.password_identities', ['driver' => 'model', 'model' => PasswordIdentity::class]);
        $config->set('auth.providers.password_machines', ['driver' => 'model', 'model' => PasswordMachine::class]);
        $config->set('auth.guards.web', ['driver' => 'jwt', 'provider' => 'password_identities', 'audience' => $audience]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'password_identities', 'audience' => $audience]);
        $config->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'password_machines', 'audience' => $audience]);
        $config->set('auth.guards.console', ['driver' => 'jwt', 'provider' => 'password_identities', 'audience' => [...$audience, 'require_verified_identifier' => true]]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Freeze every clock the package reads (Carbon, `CarbonImmutable` and the
     * JWT library's) at the time, or release them.
     *
     * @param  ?\Carbon\CarbonImmutable  $time
     * @return void
     */
    protected static function freezeClock(?CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time?->getTimestamp();
    }

    /**
     * Persist an active identity with the shared password and a verified email
     * address.
     *
     * @param  string  $email
     * @param  array<string, mixed>  $attributes
     * @return \Tests\Integration\Fixtures\PasswordIdentity
     */
    protected static function seedPasswordIdentity(string $email = 'ada@example.test', array $attributes = []): PasswordIdentity
    {
        $identity = new PasswordIdentity;

        $identity->forceFill([
            'email'             => $email,
            'email_verified_at' => '2026-01-01 00:00:00',
            'password'          => app(Hasher::class)->make(self::PASSWORD),
            'is_active'         => true,
            ...$attributes,
        ])->save();

        return $identity;
    }

    /**
     * Sign the identity with the email in through the guard's password method,
     * as a fresh request, and return the session.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    protected function signInWithPassword(string $guard = 'web', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session, "The password sign-in through [{$guard}] failed.");

        return $session;
    }
}
