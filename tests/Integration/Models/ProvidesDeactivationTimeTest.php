<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ProvidesDeactivationTime;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeactivation;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\DeactivatableMember;
use Tests\Integration\Fixtures\DeactivatableMembership;
use Tests\Integration\Fixtures\DeactivatableTenant;
use Tests\TestCase;

/**
 * Integration tests of active state stored as a nullable `deactivated_at` time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnDeactivation::class)]
#[CoversTrait(ProvidesDeactivationTime::class)]
final class ProvidesDeactivationTimeTest extends TestCase
{
    use InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string Guard over the members. */
    private const string GUARD = 'deactivatables';

    /** @var string The member's email address. */
    private const string EMAIL = 'member@example.test';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and add a route behind the `auth`
     * middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        foreach (['deactivatable_tenants', 'deactivatable_members', 'deactivatable_memberships'] as $table) {
            Schema::create($table, static function (Blueprint $blueprint) use ($table): void {
                $blueprint->increments('id');

                match ($table) {
                    'deactivatable_tenants'     => $blueprint->string('name'),
                    'deactivatable_members'     => [$blueprint->string('email')->unique(), $blueprint->string('password')],
                    'deactivatable_memberships' => [$blueprint->unsignedInteger('identity_id'), $blueprint->unsignedInteger('tenant_id')],
                };

                $blueprint->timestamp('deactivated_at')->nullable();
                $blueprint->timestamps();
            });
        }

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['identity' => Auth::id()]);
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (['deactivatable_memberships', 'deactivatable_members', 'deactivatable_tenants'] as $table) {
            Schema::dropIfExists($table);
        }

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A member, membership or tenant with a deactivation time cannot sign in,
     * each refused with its own reason; with none set, the sign-in goes ahead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingWithADeactivationTimeSignsIn(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $member->forceFill(['deactivated_at' => $this->now->subDay()])->save();

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->signIn()->reason);

        $member->forceFill(['deactivated_at' => null])->save();
        $membership->forceFill(['deactivated_at' => $this->now->addYear()])->save();

        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $this->signIn()->reason);

        $membership->forceFill(['deactivated_at' => null])->save();
        $tenant->forceFill(['deactivated_at' => $this->now->toDateTimeString()])->save();

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->signIn()->reason);

        $tenant->forceFill(['deactivated_at' => null])->save();

        self::assertTrue($this->signIn()->isSignedIn());
    }

    /**
     * A session stops at the `auth` middleware and on refresh as soon as a time
     * is set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionStopsAsSoonAsATimeIsSet(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $this->bearer($session)->assertOk();

        DeactivatableMembership::query()->whereKey($membership->getKey())->update(['deactivated_at' => $this->now->toDateTimeString()]);

        $this->bearer($session)->assertUnauthorized();

        DeactivatableMembership::query()->whereKey($membership->getKey())->update(['deactivated_at' => null]);
        DeactivatableTenant::query()->whereKey($tenant->getKey())->update(['deactivated_at' => $this->now->toDateTimeString()]);

        $refreshed = $this->sessions(self::GUARD)->refresh(PresentedRefreshToken::fromBody($session->tokens->refreshToken?->reveal() ?? ''), self::requestClient());

        self::assertSame(FailureReason::TENANT_INACTIVE, $refreshed->reason);
    }

    /**
     * A member read without its deactivation column cannot say whether it is
     * active, so asking throws rather than reading it as either.
     *
     * @return void
     */
    public function testAMemberReadWithoutItsDeactivationTimeFailsLoudly(): void
    {
        $this->seedMember();

        $partial = DeactivatableMember::query()->select(['id', 'email', 'password'])->firstOrFail();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `deactivated_at` attribute is not loaded. Select the column or override getDeactivatedAtName().');

        $partial->isActive();
    }

    /**
     * The observer ends the member's sessions only when its time is first set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheObserverEndsSessionsWhenTheTimeIsFirstSet(): void
    {
        DeactivatableMember::observe(RevokeSessionsOnDeactivation::class);

        [$member] = $this->seedMember();

        $signedIn = $this->signedIn();

        $member->forceFill(['deactivated_at' => $this->now])->save();

        self::assertTrue(self::isRevoked($signedIn->record->getKey()));

        $kept = (new Session)->forceFill([
            ...self::liveSession(self::GUARD),
            'authenticatable_type' => DeactivatableMember::class,
            'authenticatable_id'   => (string) $member->id,
        ]);

        $kept->save();

        $member->forceFill(['deactivated_at' => $this->now->addHour()])->save();
        $member->forceFill(['deactivated_at' => null])->save();

        self::assertFalse(self::isRevoked($kept->getKey()));

        $member->forceFill(['deactivated_at' => $this->now->addDay()])->save();

        self::assertTrue(self::isRevoked($kept->getKey()));
    }

    /**
     * Register the session guards and the members' guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.' . self::GUARD, ['driver' => 'model', 'model' => DeactivatableMember::class]);
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => self::GUARD, 'application' => ['methods' => ['password']]]);
    }

    /**
     * Persist an active tenant, a member and its membership, each with its
     * deactivation time.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\DeactivatableMember, 1: \Tests\Integration\Fixtures\DeactivatableMembership, 2: \Tests\Integration\Fixtures\DeactivatableTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMember(): array
    {
        $tenant     = DeactivatableTenant::query()->create(['name' => 'Tenant', 'deactivated_at' => null]);
        $member     = DeactivatableMember::query()->create(['email' => self::EMAIL, 'password' => app(Hasher::class)->make(self::PASSWORD), 'deactivated_at' => null]);
        $membership = DeactivatableMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'deactivated_at' => null]);

        return [$member, $membership, $tenant];
    }

    /**
     * Sign the member in with its password.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signIn(): SignInResult
    {
        return $this->sessions(self::GUARD)->signIn('password', self::credentials(self::EMAIL), self::requestContext());
    }

    /**
     * Sign the member in and return its session.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->signIn()->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Send a request with the session's access token to the protected route.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(SignedInSession $session): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me');
    }

    /**
     * Whether the session with the key is revoked.
     *
     * @param  mixed  $key
     * @return bool
     */
    private static function isRevoked(mixed $key): bool
    {
        return Session::query()->whereKey($key)->value('revoked_at') !== null;
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
