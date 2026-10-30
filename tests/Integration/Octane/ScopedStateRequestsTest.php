<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Facades\Auth as Authentication;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Listeners\TrackCredentialAttempts;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * End-to-end tests for the rehash mark served by one Laravel Octane worker. The
 * mark is bound with `scoped()`, so each request's sandbox resolves its own,
 * and Octane forgets the booted application's scoped instances once a request
 * ends: whatever an attempt one request abandoned left on its mark is gone for
 * the next. Within a request, the attempt that marks a rehash and the observer
 * that reads the mark share it, though the event dispatcher builds the observer
 * with the application the worker booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Rehashing::class)]
#[CoversClass(TrackCredentialAttempts::class)]
#[CoversClass(RevokeDevicesOnPasswordChange::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class ScopedStateRequestsTest extends TestCase
{
    use InteractsWithSessions, ServesRequestsThroughOctane;

    /** @var list<\SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing> The mark each request resolved, in order. */
    private array $marks = [];

    /**
     * Create the tables and add the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::post('/sign-in', static fn (): array => ['signed_in' => Authentication::sessions('api')->signIn('password', self::credentials())->isSignedIn()]);

        Route::post('/web/abandon', function (): array {
            try {
                Auth::guard('web')->attemptWhen(self::credentials(), static function (): never {
                    throw new \RuntimeException('callback failed');
                });
            } catch (\RuntimeException) { // @phpstan-ignore catch.neverThrown
                $this->marks[] = app(Rehashing::class);
            }

            return ['abandoned' => true];
        });

        Route::post('/web/attempt', function (): array {
            $attempted = Auth::guard('web')->attempt(self::credentials());

            $this->marks[] = app(Rehashing::class);

            return ['attempted' => $attempted];
        });

        Route::post('/password', function (): array {
            $identity           = IntegrationIdentity::query()->firstOrFail();
            $identity->password = app(Hasher::class)->make(self::PASSWORD);
            $identity->save();

            $this->marks[] = app(Rehashing::class);

            return ['saved' => true];
        });
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A mark the booted application resolved before the worker started serves
     * the first request only: Octane forgets it once that request ends, and
     * each later request resolves a mark of its own.
     *
     * @return void
     */
    public function testEachRequestResolvesAMarkOfItsOwn(): void
    {
        $booted = $this->app?->make(Rehashing::class);

        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('POST', '/web/attempt'))->assertOk();
        $this->serve(self::octaneRequest('POST', '/web/attempt'))->assertOk();
        $this->serve(self::octaneRequest('POST', '/web/attempt'))->assertOk();

        self::assertSame($booted, $this->marks[0]);
        self::assertNotSame($this->marks[0], $this->marks[1]);
        self::assertNotSame($this->marks[1], $this->marks[2]);
    }

    /**
     * An attempt one request abandons leaves its user marked on that request's
     * mark only: the next request's save of a fresh hash of the same password
     * is answered as the change it is, and ends the user's sessions.
     *
     * @return void
     */
    public function testAnAttemptAbandonedInOneRequestMarksNothingInTheNext(): void
    {
        $this->seedSignedInIdentity();

        $this->serve(self::octaneRequest('POST', '/web/abandon'))->assertExactJson(['abandoned' => true]);
        $this->serve(self::octaneRequest('POST', '/password'))->assertExactJson(['saved' => true]);

        self::assertNotSame($this->marks[0], $this->marks[1]);
        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Laravel's rehash of an outdated hash on `attempt()`, saved through its
     * Eloquent user provider, is no change of password: the observer, which the
     * dispatcher builds with the booted application, reads the request's own
     * mark, and revokes nothing. A save in a later request, once the attempt
     * has ended, is a change.
     *
     * @return void
     */
    public function testLaravelsRehashOnAttemptRevokesNothing(): void
    {
        $this->seedSignedInIdentity();

        $outdated = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 5]);

        DB::table('integration_identities')->update(['password' => $outdated]);

        $this->serve(self::octaneRequest('POST', '/web/attempt'))->assertExactJson(['attempted' => true]);

        self::assertNotSame($outdated, DB::table('integration_identities')->value('password'));
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        $this->serve(self::octaneRequest('POST', '/password'))->assertExactJson(['saved' => true]);

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Configure the guards, Laravel's session guard over an Eloquent user
     * provider of the identity model, and an array session.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.users', ['driver' => 'eloquent', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.timebox_duration', 1);
        $config->set('session.driver', 'array');
    }

    /**
     * Seed an identity, sign it in on the `api` guard through a booted worker,
     * and observe its model for changes of password.
     *
     * @return void
     */
    private function seedSignedInIdentity(): void
    {
        $this->seedIdentity();
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('POST', '/sign-in'))->assertExactJson(['signed_in' => true]);

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);
    }
}
