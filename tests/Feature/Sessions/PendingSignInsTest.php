<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingFactor;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for the sign-ins waiting for a further factor: what issuing one
 * stores (never the secret), which tokens find one (live, of the guard, for an
 * identity and principal that still resolve as recorded), when its proven
 * device still counts, and that it is used up exactly once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSignIns::class)]
#[CoversClass(FoundPendingSignIn::class)]
#[CoversClass(PendingFactor::class)]
#[CoversClass(PendingSignIn::class)]
final class PendingSignInsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Issuing stores who signed in, as whom, how, from which client, on which
     * proven device at which digest, and until when, but only the digest of the
     * token's secret; the token is the row's identifier and the secret.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIssueStoresTheSignInButNotTheSecret(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);
        $context  = new SignInContext(new ClientContext('192.0.2.1', 'Pending/1.0'), 'Phone', 'iOS');
        $pending  = $this->pendings()->issue('api', (new AdmittedSignIn($identity, $identity, null))->on($device), 'password', 'email', $context, $this->now);

        [$id, $secret] = explode('.', $pending->token, 2);

        $row = PendingSignIn::query()->whereKey($id)->firstOrFail();

        self::assertTrue(RefreshTokenHasher::verify($secret, $row->token_digest));
        self::assertStringNotContainsString($secret, (string) json_encode(DB::table('pending_sign_ins')->where('id', $id)->first()));
        self::assertSame(PendingSignIn::ADDITIONAL_FACTOR, $row->purpose);
        self::assertSame('api', $row->guard);
        self::assertSame('password', $row->sign_in_method);
        self::assertSame('email', $row->identifier_type);
        self::assertSame(IntegrationIdentity::class, $row->authenticatable_type);
        self::assertSame((string) $identity->id, $row->authenticatable_id);
        self::assertSame(IntegrationIdentity::class, $row->principal_type);
        self::assertSame((string) $identity->id, $row->principal_id);
        self::assertSame('Phone', $row->client_name);
        self::assertSame('iOS', $row->platform);
        self::assertSame('192.0.2.1', $row->created_ip);
        self::assertSame('Pending/1.0', $row->created_user_agent);
        self::assertSame($device->getKey(), $row->device_id);
        self::assertSame($device->getRefreshKey(), $row->device_refresh_key);
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), $row->expires_at->getTimestamp());
        self::assertArrayNotHasKey('token_digest', $row->toArray());
        self::assertArrayNotHasKey('device_refresh_key', $row->toArray());

        self::assertSame('api', $pending->guard);
        self::assertSame($identity, $pending->identity);
        self::assertSame($identity, $pending->principal);
        self::assertNull($pending->tenant);
        self::assertSame('password', $pending->method);
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), $pending->expiresAt->getTimestamp());
        self::assertSame($device, $pending->provenDevice);
    }

    /**
     * Rows of `[configured lifetime, seconds]`: lifetimes accepted as integers
     * or as digit strings, as `env()` returns them.
     *
     * @return iterable<string, array{0: mixed, 1: int}>
     */
    public static function provideLifetimes(): iterable
    {
        yield from [
            'shortest'     => [30, 30],
            'longest'      => [3600, 3600],
            'digit string' => ['600', 600],
        ];
    }

    /**
     * The pending credential lives for the configured lifetime.
     *
     * @param  mixed  $configured
     * @param  int  $seconds
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLifetimes')]
    public function testThePendingCredentialLivesForTheConfiguredLifetime(mixed $configured, int $seconds): void
    {
        config()->set('authentication.sign_in.pending_ttl_seconds', $configured);

        $pending = $this->issue($this->seedIdentity());

        self::assertSame($this->now->addSeconds($seconds)->getTimestamp(), $pending->expiresAt->getTimestamp());
    }

    /**
     * Without the setting, a pending credential lives five minutes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePendingCredentialLivesFiveMinutesByDefault(): void
    {
        config()->set('authentication.sign_in', ['password_identifier' => 'email', 'pending_table' => 'pending_sign_ins']);

        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $this->issue($this->seedIdentity())->expiresAt->getTimestamp());
    }

    /**
     * Rows of `[configured lifetime]` that fail closed.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideInvalidLifetimes(): iterable
    {
        yield from [
            'too short'            => [29],
            'too long'             => [3601],
            'zero'                 => [0],
            'negative'             => [-300],
            'padded digit string'  => ['0300'],
            'signed digit string'  => ['+300'],
            'decimal'              => [300.0],
            'trailing newline'     => ["300\n"],
            'null'                 => [null],
            'words'                => ['five minutes'],
            'too long as a string' => ['3601'],
        ];
    }

    /**
     * A lifetime that is not an integer from 30 to 3600 seconds fails closed
     * naming the setting, and nothing is stored.
     *
     * @param  mixed  $configured
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideInvalidLifetimes')]
    public function testAMalformedLifetimeFailsClosed(mixed $configured): void
    {
        config()->set('authentication.sign_in.pending_ttl_seconds', $configured);

        $identity = $this->seedIdentity();

        try {
            $this->issue($identity);
            self::fail('Expected the lifetime to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('authentication.sign_in.pending_ttl_seconds must be an integer from 30 to 3600 seconds.', $exception->getMessage());
        }

        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * Only an Eloquent identity can wait for a factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIssueRefusesAnIdentityThatIsNotAModel(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('A sign-in can only wait for a further factor for an Eloquent identity; %s is not a model.', $identity::class));

        $this->pendings()->issue('api', new AdmittedSignIn($identity, \Mockery::mock(Principal::class), null), 'password', null, $this->context(), $this->now);
    }

    /**
     * A live pending sign-in is found for its token with its identity and
     * principal reloaded, and finding it does not use it up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFindsALivePendingSignInWithoutUsingItUp(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->issue($identity);
        $found    = $this->find($pending->token);

        self::assertNotNull($found);
        self::assertInstanceOf(IntegrationIdentity::class, $found->factor->identity);
        self::assertTrue($found->factor->identity->is($identity));
        self::assertNotSame($identity, $found->factor->identity);
        self::assertSame($found->factor->identity, $found->factor->principal);
        self::assertSame($pending->token, $found->factor->token);
        self::assertSame('api', $found->factor->guard);
        self::assertSame($pending->expiresAt->getTimestamp(), $found->factor->expiresAt->getTimestamp());
        self::assertNull($found->device);
        self::assertSame(1, PendingSignIn::query()->count());
        self::assertNotNull($this->find($pending->token));
    }

    /**
     * Rows of `[token]` that cannot name a pending sign-in, so no query is made
     * for them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedTokens(): iterable
    {
        yield from [
            'empty'             => [''],
            'no separator'      => ['0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70'],
            'no secret'         => ['0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70.'],
            'not a uuid'        => ['pending.secret'],
            'three segments'    => ['header.payload.signature'],
            'uuid with a space' => [' 0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70.secret'],
        ];
    }

    /**
     * A token whose identifier is not a UUID is rejected without a query.
     *
     * @param  string  $token
     * @return void
     */
    #[DataProvider('provideMalformedTokens')]
    public function testAMalformedTokenIsRejectedWithoutAQuery(string $token): void
    {
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertNull($this->pendings()->find('api', $token, \Mockery::mock(IdentityProvider::class), \Mockery::mock(PrincipalResolver::class), $this->now));
        self::assertSame(0, $queries);
    }

    /**
     * A token with the wrong secret, for another guard, for a pending sign-in
     * of another purpose, or at its expiry finds nothing; nor does an unknown
     * identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheLiveTokenOfTheGuardFindsThePendingSignIn(): void
    {
        $pending = $this->issue($this->seedIdentity());

        [$id, $secret] = explode('.', $pending->token, 2);

        self::assertNull($this->find($id . '.not-the-secret'));
        self::assertNull($this->find($pending->token . '.extra'));
        self::assertNull($this->find('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70.' . $secret));
        self::assertNull($this->pendings()->find('admin', $pending->token, $this->provider(), $this->resolver(), $this->now));

        PendingSignIn::query()->whereKey($id)->update(['purpose' => 'verify_identifier']);

        self::assertNull($this->find($pending->token));

        PendingSignIn::query()->whereKey($id)->update(['purpose' => PendingSignIn::ADDITIONAL_FACTOR]);

        self::assertNotNull($this->pendings()->find('api', $pending->token, $this->provider(), $this->resolver(), $this->now->addSeconds(299)));
        self::assertNull($this->pendings()->find('api', $pending->token, $this->provider(), $this->resolver(), $this->now->addSeconds(300)));
    }

    /**
     * The identity must come back through the guard's provider as the very
     * owner the pending sign-in recorded, and the principal through the hinted
     * path as the one it recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityAndPrincipalMustStillResolveAsRecorded(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->issue($identity);

        [$id] = explode('.', $pending->token, 2);

        PendingSignIn::query()->whereKey($id)->update(['authenticatable_type' => 'another-model']);
        self::assertNull($this->find($pending->token));

        PendingSignIn::query()->whereKey($id)->update(['authenticatable_type' => IntegrationIdentity::class, 'authenticatable_id' => '999']);
        self::assertNull($this->find($pending->token));

        PendingSignIn::query()->whereKey($id)->update(['authenticatable_id' => (string) $identity->id, 'principal_type' => 'another-model']);
        self::assertNull($this->find($pending->token));

        PendingSignIn::query()->whereKey($id)->update(['principal_type' => IntegrationIdentity::class]);
        self::assertNotNull($this->find($pending->token));

        $impostor = \Mockery::mock(IdentityProvider::class);
        $impostor->shouldReceive('retrieveById')->once()->with((string) $identity->id)->andReturn(\Mockery::mock(Identity::class));

        self::assertNull($this->pendings()->find('api', $pending->token, $impostor, $this->resolver(), $this->now));

        $identity->delete();
        self::assertNull($this->find($pending->token));
    }

    /**
     * A 3D pending sign-in comes back as its recorded membership with the
     * tenant it acts within while that tenant may authenticate, and not once it
     * names another member's membership.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembershipMustStillBeTheMembersOwn(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();
        [, $foreign]                    = $this->seedMember('other@example.test', $tenant);

        $pending = $this->pendings()->issue('members', new AdmittedSignIn($member, $membership, $tenant), 'password', 'email', $this->context(), $this->now);

        [$id] = explode('.', $pending->token, 2);

        $found = $this->findOn('members', $pending->token);

        self::assertNotNull($found);
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), IdentifierCoercion::stringify($found->factor->principal->getPrincipalIdentifier()));
        self::assertSame($tenant->getKey(), $found->factor->tenant?->getTenantIdentifier());

        PendingSignIn::query()->whereKey($id)->update(['principal_id' => IdentifierCoercion::stringify($foreign->getKey())]);

        self::assertNull($this->findOn('members', $pending->token));

        PendingSignIn::query()->whereKey($id)->update(['principal_id' => IdentifierCoercion::stringify($membership->getKey())]);

        $tenant->forceFill(['is_active' => false])->save();

        $inactive = $this->findOn('members', $pending->token);

        self::assertNotNull($inactive);
        self::assertNull($inactive->factor->tenant);
    }

    /**
     * The proven device still counts when it is the identity's live session of
     * the guard for the principal at the digest it was proven against;
     * otherwise the pending sign-in is found without it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProvenDeviceCountsOnlyWhileItIsUnchanged(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);
        $pending  = $this->pendings()->issue('api', (new AdmittedSignIn($identity, $identity, null))->on($device), 'password', 'email', $this->context(), $this->now);

        self::assertSame($device->getKey(), $this->find($pending->token)?->device?->getKey());
        self::assertSame($device->getKey(), $this->find($pending->token)?->factor->provenDevice?->getDeviceIdentifier());

        $changes = [
            ['refresh_key' => RefreshTokenHasher::hash('rotated')],
            ['revoked_at' => $this->now->format('Y-m-d H:i:s')],
            ['guard' => 'admin'],
            ['principal_id' => '999'],
            ['authenticatable_id' => '999'],
        ];

        foreach ($changes as $change) {

            $original = (array) DB::table('devices')->where('id', $device->getKey())->first();

            DB::table('devices')->where('id', $device->getKey())->update($change);

            $found = $this->find($pending->token);

            self::assertNotNull($found);
            self::assertNull($found->device);
            self::assertNull($found->factor->provenDevice);

            DB::table('devices')->where('id', $device->getKey())->update($original);
        }

        DB::table('devices')->where('id', $device->getKey())->update(['refresh_key' => null]);
        PendingSignIn::query()->update(['device_refresh_key' => null]);

        self::assertNull($this->find($pending->token)?->device);

        $device->delete();

        self::assertNull($this->find($pending->token)?->device);
    }

    /**
     * A pending sign-in is used up once: the first consume deletes it, a second
     * one deletes nothing, and so does one with the wrong secret or at its
     * expiry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInIsUsedUpOnce(): void
    {
        $found = $this->find($this->issue($this->seedIdentity())->token);

        self::assertNotNull($found);

        $forged = new FoundPendingSignIn($found->pending, 'not-the-secret', $found->factor, null);

        self::assertFalse($this->pendings()->consume($forged, $this->now));
        self::assertFalse($this->pendings()->consume($found, $this->now->addSeconds(300)));
        self::assertTrue($this->pendings()->consume($found, $this->now->addSeconds(299)));
        self::assertFalse($this->pendings()->consume($found, $this->now));
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * A pending sign-in keeps the windows of the attempt-limit slots its
     * sign-in took, and gives them back as a granted reservation of the guard's
     * sign-in flow, for the identifier type and IP address it recorded; one
     * that took none gives back nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSlotsTheSignInTookAreKeptForCompletion(): void
    {
        $identity = $this->seedIdentity();
        $context  = new SignInContext(new ClientContext('192.0.2.1', 'Pending/1.0'));
        $windows  = ['identifier-key' => '2026-04-06 12:05:00', 'ip-key' => '2026-04-06 12:05:00'];
        $kept     = $this->pendings()->issue('api', new AdmittedSignIn($identity, $identity, null), 'password', 'email', $context, $this->now, $windows);
        $none     = $this->pendings()->issue('api', new AdmittedSignIn($identity, $identity, null), 'sso', null, $context, $this->now);

        $reservation = PendingSignIns::reservation(PendingSignIn::query()->whereKey(explode('.', $kept->token, 2)[0])->firstOrFail());

        self::assertNotNull($reservation);
        self::assertTrue($reservation->granted());
        self::assertSame($windows, $reservation->windows);
        self::assertSame('api', $reservation->subject->guard);
        self::assertSame(AttemptFlow::SIGN_IN, $reservation->subject->flow);
        self::assertNull($reservation->subject->identifier);
        self::assertSame('email', $reservation->subject->identifierType);
        self::assertSame('192.0.2.1', $reservation->subject->ip);
        self::assertNull(PendingSignIns::reservation(PendingSignIn::query()->whereKey(explode('.', $none->token, 2)[0])->firstOrFail()));
        self::assertNull(PendingSignIn::query()->whereKey(explode('.', $none->token, 2)[0])->value('attempt_windows'));
    }

    /**
     * Discarding uses the live pending sign-in of the guard up, once, while its
     * token holds the secret and it has not expired, and needs nothing it
     * records to resolve.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDiscardUsesTheLivePendingSignInUpOnce(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->issue($identity);
        $id       = explode('.', $pending->token, 2)[0];

        $identity->delete();

        self::assertFalse($this->pendings()->discard('admin', $pending->token, $this->now));
        self::assertFalse($this->pendings()->discard('api', $id . '.not-the-secret', $this->now));
        self::assertFalse($this->pendings()->discard('api', $pending->token, $this->now->addSeconds(300)));
        self::assertTrue($this->pendings()->discard('api', $pending->token, $this->now->addSeconds(299)));
        self::assertFalse($this->pendings()->discard('api', $pending->token, $this->now));
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * The context of the sign-in is rebuilt from what the pending one recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextIsTheRecordedOne(): void
    {
        $identity = $this->seedIdentity();
        $context  = new SignInContext(new ClientContext('192.0.2.1', 'Pending/1.0'), 'Phone', 'iOS');
        $pending  = $this->pendings()->issue('api', new AdmittedSignIn($identity, $identity, null), 'password', null, $context, $this->now);
        $row      = PendingSignIn::query()->whereKey(explode('.', $pending->token, 2)[0])->firstOrFail();
        $rebuilt  = PendingSignIns::context($row);

        self::assertNull($row->identifier_type);
        self::assertSame('192.0.2.1', $rebuilt->client->ip);
        self::assertSame('Pending/1.0', $rebuilt->client->userAgent);
        self::assertSame('Phone', $rebuilt->clientName);
        self::assertSame('iOS', $rebuilt->platform);
        self::assertNull($rebuilt->principal);
        self::assertNull($rebuilt->refreshToken);
    }

    /**
     * Expired pending sign-ins, and only those, are pruned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiredPendingSignInsArePruned(): void
    {
        $identity = $this->seedIdentity();
        $live     = $this->issue($identity);
        $expired  = $this->pendings()->issue('api', new AdmittedSignIn($identity, $identity, null), 'password', null, $this->context(), $this->now->subMinutes(5));

        self::assertSame([explode('.', $expired->token, 2)[0]], (new PendingSignIn)->prunable()->pluck('id')->all());
        self::assertNotNull($this->find($live->token));
    }

    /**
     * Configure the guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The pending sign-ins on the application's configuration.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingSignIns
     */
    private function pendings(): PendingSignIns
    {
        return new PendingSignIns(app(ConfigRepository::class));
    }

    /**
     * Issue a 2D pending sign-in for the identity on the `api` guard.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingFactor
     *
     * @throws \Throwable
     */
    private function issue(IntegrationIdentity $identity): PendingFactor
    {
        return $this->pendings()->issue('api', new AdmittedSignIn($identity, $identity, null), 'password', 'email', $this->context(), $this->now);
    }

    /**
     * Find the pending sign-in of the `api` guard the token names, now.
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn
     *
     * @phpstan-impure
     */
    private function find(#[\SensitiveParameter] string $token): ?FoundPendingSignIn
    {
        return $this->findOn('api', $token);
    }

    /**
     * Find the pending sign-in of the guard the token names, now.
     *
     * @param  string  $guard
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn
     *
     * @phpstan-impure
     */
    private function findOn(string $guard, #[\SensitiveParameter] string $token): ?FoundPendingSignIn
    {
        return $this->pendings()->find($guard, $token, $this->provider($guard), $this->resolver($guard), $this->now);
    }

    /**
     * The guard's identity provider.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Contracts\IdentityProvider
     */
    private function provider(string $guard = 'api'): IdentityProvider
    {
        return $this->freshGuard($guard)->getProvider();
    }

    /**
     * The guard's principal resolver.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver
     */
    private function resolver(string $guard = 'api'): PrincipalResolver
    {
        return $this->freshGuard($guard)->getPrincipalResolver();
    }

    /**
     * A sign-in context from a known client.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(): SignInContext
    {
        return new SignInContext(new ClientContext('192.0.2.1', 'Pending/1.0'));
    }

    /**
     * Persist a live device of the `api` guard for the 2D identity, holding a
     * refresh credential.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(IntegrationIdentity $identity): Device
    {
        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->id,
            'principal_type'       => IntegrationIdentity::class,
            'principal_id'         => (string) $identity->id,
            'guard'                => 'api',
            'refresh_key'          => RefreshTokenHasher::hash('current'),
            'idle_expires_at'      => $this->now->addDays(30),
            'absolute_expires_at'  => $this->now->addDays(180),
        ])->save();

        return Device::query()->whereKey($device->getKey())->firstOrFail();
    }
}
