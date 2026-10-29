<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\PendingFactor;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Fixtures\Sessions\TwoSecretSignIn;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\UnscopedMembershipResolver;
use Tests\TestCase;

/**
 * End-to-end tests for sign-ins that need a further factor: the pending sign-in
 * the session service hands out instead of a session, looking it up, and
 * completing it into a session once, with every check made again, against a
 * real database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
final class PendingFactorSessionServiceTest extends TestCase
{
    use InteractsWithRateLimits, InteractsWithSessions;

    /** @var string IP address the completion request comes from. */
    private const string COMPLETION_IP = '198.51.100.9';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var list<?string> Device identifiers the factor policy was told of, in order. */
    private array $proven = [];

    /**
     * Freeze the clocks, create the tables, require a factor of every sign-in,
     * and add a route behind the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeClocksAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->byDefault()->andReturnUsing(function (AdditionalFactorContext $context): bool {
            $this->proven[] = $context->provenDevice === null ? null : (string) $context->provenDevice->getDeviceIdentifier(); // @phpstan-ignore cast.string

            return true;
        });

        app()->instance(AdditionalFactorPolicy::class, $factors);

        Route::middleware('auth:api')->get('/me', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);
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
     * A sign-in that needs a factor starts no session and hands out a pending
     * sign-in; looking it up does not use it up; completing it from another
     * client starts the session on a device created from the original sign-in's
     * client and last used by the completing one, binds the guard, and
     * dispatches the bind events, `DeviceCreated` and `SignedIn` (both with the
     * completing client), but no `Attempting`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInCompletesIntoASession(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->pendingFor('password', 'Phone', 'iOS');

        self::assertSame(0, Device::query()->count());

        $looked = $this->sessions()->pending($pending->token);

        self::assertNotNull($looked);
        self::assertSame($pending->token, $looked->token);
        self::assertSame('api', $looked->guard);
        self::assertSame('password', $looked->method);
        self::assertTrue($looked->identity instanceof IntegrationIdentity && $looked->identity->is($identity));
        self::assertSame($looked->identity, $looked->principal);
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), $looked->expiresAt->getTimestamp());
        self::assertNull($looked->provenDevice);
        self::assertSame(1, PendingSignIn::query()->count());

        $this->recordEvents([Attempting::class, Validated::class, Login::class, DeviceCreated::class, SignedIn::class, Failed::class, AuthenticationFailed::class]);

        $guard  = $this->completionGuard();
        $result = $guard->sessions()->complete($pending->token);

        self::assertTrue($result->isSignedIn());
        self::assertSame([Validated::class, Login::class, DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame('password', $this->recordedEvent(SignedIn::class)->context->method);
        self::assertSame(self::COMPLETION_IP, $this->recordedEvent(SignedIn::class)->context->client->ip);
        self::assertSame(self::COMPLETION_IP, $this->recordedEvent(DeviceCreated::class)->context->client->ip);
        self::assertSame(0, PendingSignIn::query()->count());

        $session = $result->session;

        self::assertNotNull($session);
        self::assertSame($session->identity, $guard->user());
        self::assertSame($session->device, $guard->device());

        $device = Device::query()->whereKey($session->device->getKey())->firstOrFail();

        self::assertSame('password', $device->getSignInMethod());
        self::assertSame('email', $device->getSignInIdentifierType());
        self::assertSame('Phone', $device->client_name);
        self::assertSame('iOS', $device->platform);
        self::assertSame(self::CLIENT_IP, $device->created_ip);
        self::assertSame(self::CLIENT_AGENT, $device->created_user_agent);
        self::assertSame(self::COMPLETION_IP, $device->last_used_ip);
        self::assertNotSame(self::CLIENT_AGENT, $device->last_used_user_agent);

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken])->getJson('/me')->assertOk()->assertJson(['device' => $device->getKey()]);
    }

    /**
     * A pending sign-in completes once: a second completion, like any token
     * that names no live pending sign-in of the guard, fails as
     * `pending_invalid` without saying why, and `pending()` no longer finds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInCompletesOnlyOnce(): void
    {
        $this->seedIdentity();

        $pending = $this->pendingFor();

        self::assertTrue($this->sessions()->complete($pending->token)->isSignedIn());

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $again = $this->completionGuard()->sessions()->complete($pending->token);

        self::assertSame(FailureReason::PENDING_INVALID, $again->reason);
        self::assertNull($this->sessions()->pending($pending->token));
        self::assertNull($this->recordedEvent(Failed::class)->user);
        self::assertSame([], $this->recordedEvent(Failed::class)->credentials);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertNull($failed->context->identity);
        self::assertNull($failed->context->method);
        self::assertSame(self::COMPLETION_IP, $failed->context->client->ip);
        self::assertSame(1, Device::query()->count());
    }

    /**
     * A completion that fails its checks reports the client that tried to
     * complete it, not the one the sign-in came from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedCompletionReportsTheCompletingClient(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->pendingFor();

        $identity->forceFill(['is_active' => false])->save();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->completionGuard()->sessions()->complete($pending->token)->reason);
        self::assertSame(self::COMPLETION_IP, $this->recordedEvent(AuthenticationFailed::class)->context->client->ip);
    }

    /**
     * A failure after a completion has used the pending sign-in up (here just
     * after the device is written) rolls the whole completion back: the pending
     * sign-in survives, no device is left, and the completion can be retried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureWhileCompletingKeepsThePendingSignIn(): void
    {
        $this->seedIdentity();

        $pending = $this->pendingFor();
        $failure = new \ArrayObject(['armed' => true]);

        DB::listen(static function (QueryExecuted $query) use ($failure): void {
            if ($failure['armed'] && str_starts_with(strtolower($query->sql), 'insert into') && str_contains($query->sql, 'devices')) {
                throw new \RuntimeException('failed after the write');
            }
        });

        try {
            $this->sessions()->complete($pending->token);
            self::fail('Expected the completion to fail after the write.');
        } catch (\RuntimeException $exception) {
            self::assertSame('failed after the write', $exception->getMessage());
        }

        self::assertSame(1, PendingSignIn::query()->count());
        self::assertSame(0, Device::query()->count());
        self::assertNotNull($this->sessions()->pending($pending->token));

        $failure['armed'] = false;

        self::assertTrue($this->sessions()->complete($pending->token)->isSignedIn());
        self::assertSame(1, Device::query()->count());
    }

    /**
     * An expired pending token, one for another guard, and one that is not a
     * pending token at all all fail as `pending_invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiredForeignAndMalformedTokensAreInvalid(): void
    {
        $this->seedIdentity();

        $pending = $this->pendingFor();

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions('admin')->complete($pending->token)->reason);
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete('not-a-pending-token')->reason);
        self::assertNull($this->sessions('admin')->pending($pending->token));

        $this->freezeClocksAt($this->now->addSeconds(300));

        self::assertNull($this->sessions()->pending($pending->token));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete($pending->token)->reason);
        self::assertSame(0, Device::query()->count());
    }

    /**
     * A pending token authenticates nothing: it is neither a bearer token nor a
     * refresh token.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingTokenAuthenticatesNothing(): void
    {
        $this->seedIdentity();

        $pending = $this->pendingFor();

        $this->withHeaders(['Authorization' => 'Bearer ' . $pending->token])->getJson('/me')->assertUnauthorized();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull($this->freshGuard()->refresh($pending->token));
        self::assertSame(FailureReason::TOKEN_INVALID, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(1, PendingSignIn::query()->count());
    }

    /**
     * Completion checks the sign-in again, and a check that fails still uses
     * the pending sign-in up: an identity deactivated meanwhile, a method the
     * guard no longer allows, and a principal the audience policy no longer
     * admits each fail with their reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompletionChecksTheSignInAgainAndUsesItUpWhateverTheOutcome(): void
    {
        $identity = $this->seedIdentity();

        $inactive = $this->pendingFor();

        $identity->forceFill(['is_active' => false])->save();

        $this->assertCompletionFails(FailureReason::IDENTITY_INACTIVE, $inactive);

        $identity->forceFill(['is_active' => true])->save();

        $removed  = $this->pendingFor();
        $audience = $this->audience();
        $audience->shouldReceive('allowsMethod')->with('api', 'password')->andReturnFalse();

        $this->assertCompletionFails(FailureReason::METHOD_NOT_ALLOWED, $removed);

        $audience   = $this->audience();
        $ineligible = $this->pendingFor();
        $audience->shouldReceive('admit')
            ->once()
            ->with('api', \Mockery::type(IntegrationIdentity::class), \Mockery::type(IntegrationIdentity::class), 'email')
            ->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);

        $this->assertCompletionFails(FailureReason::IDENTIFIER_UNVERIFIED, $ineligible);
    }

    /**
     * A session started elsewhere waits for its factor like any other, and is
     * admitted on completion with no identifier type; a membership whose tenant
     * was deactivated meanwhile does not complete.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompletionChecksTheTenantAndKeepsTheIdentifierType(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $started = $this->sessions('members')->start($member, null, 'sso')->pending;

        self::assertNotNull($started);

        $audience = $this->audience();
        $audience->shouldReceive('admit')->twice()->with('members', \Mockery::any(), \Mockery::any(), null)->andReturnNull();

        self::assertTrue($this->sessions('members')->complete($started->token)->isSignedIn());

        $pending = $this->sessions('members')->start($member, null, 'sso')->pending;

        self::assertNotNull($pending);

        $tenant->forceFill(['is_active' => false])->save();

        $this->assertCompletionFails(FailureReason::TENANT_INACTIVE, $pending, 'members');
    }

    /**
     * A client that proved it holds a device, and was asked for a factor,
     * continues on that device once it completes, and the factor policy was
     * told of the device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenDeviceIsContinuedOnCompletion(): void
    {
        $this->seedIdentity();

        $first = $this->signedInWithoutAFactor();

        $pending = $this->pendingFor(refreshToken: $first->tokens->refreshToken);

        self::assertSame([$first->device->getKey()], $this->proven);
        self::assertSame($first->device->getKey(), $pending->provenDevice?->getDeviceIdentifier());

        $session = $this->sessions()->complete($pending->token)->session;

        self::assertNotNull($session);
        self::assertFalse($session->deviceCreated);
        self::assertSame($first->device->getKey(), $session->device->getKey());
        self::assertSame(1, Device::query()->count());
        self::assertSame('email', Device::query()->sole()->getSignInIdentifierType());
    }

    /**
     * A proven device that changes after the factor was asked for is not
     * continued: a refresh before the completion makes it unknown to the
     * pending sign-in, and one in the middle of the completion makes the swap
     * miss; either way the completion starts on a new device, which records the
     * sign-in's identifier type.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenDeviceThatChangedIsNotContinued(): void
    {
        $this->seedIdentity();

        $first   = $this->signedInWithoutAFactor();
        $before  = $this->pendingFor(refreshToken: $first->tokens->refreshToken);
        $rotated = $this->freshGuard()->refresh($first->tokens->refreshToken);

        self::assertNotNull($rotated);
        self::assertNull($this->sessions()->pending($before->token)?->provenDevice);
        self::assertTrue($this->sessions()->complete($before->token)->session?->deviceCreated);

        $during = $this->pendingFor(refreshToken: $rotated->refreshToken);

        $this->onStatement('delete from', static function () use ($first): void {
            Device::query()->whereKey($first->device->getKey())->update(['refresh_key' => RefreshTokenHasher::hash('rotated-in-parallel')]);
        });

        $result = $this->sessions()->complete($during->token);

        self::assertTrue($result->session?->deviceCreated);
        self::assertSame('email', Device::query()->whereKey($result->session->device->getKey())->value('sign_in_identifier_type'));
        self::assertSame(RefreshTokenHasher::hash('rotated-in-parallel'), Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRefreshKey());
    }

    /**
     * A completion whose delete finds the pending sign-in already gone, used up
     * by another between this one's lookup and its delete, fails as
     * `pending_invalid` and starts nothing. `ConcurrentPendingCompletionTest`
     * races two completions on separate connections.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionWhoseDeleteFindsTheRowGoneStartsNothing(): void
    {
        $this->seedIdentity();

        $pending = $this->pendingFor();

        $this->onStatement('delete from', static function (): void {
            DB::table('pending_sign_ins')->delete();
        });

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete($pending->token)->reason);
        self::assertSame(0, Device::query()->count());
    }

    /**
     * When the proven device changes before a sign-in can continue on it, the
     * factor policy is asked again without the device, and a pending sign-in it
     * then asks for carries no device; its completion records the sign-in's
     * identifier type.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorIsReconsideredWithoutADeviceThatChanged(): void
    {
        $identity = $this->seedIdentity();

        $first = $this->signedInWithoutAFactor();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->twice()->andReturnUsing(function (AdditionalFactorContext $context) use ($first): bool {

            if ($context->provenDevice !== null) {

                Device::query()->whereKey($first->device->getKey())->update(['refresh_key' => RefreshTokenHasher::hash('rotated-in-parallel')]);

                return false;
            }

            return true;
        });

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken);
        $result  = $this->sessions()->signIn('password', self::credentials(), $context);

        self::assertTrue($result->requiresFactor());
        self::assertNull($result->pending?->provenDevice);
        self::assertNull(PendingSignIn::query()->firstOrFail()->device_id);
        self::assertSame([1, 1], [$this->identifierHits(), $this->accountHits($identity)]);

        $completed = $this->sessions()->complete((string) $result->pending?->token)->session;

        self::assertNotNull($completed);
        self::assertSame('email', Device::query()->whereKey($completed->device->getKey())->value('sign_in_identifier_type'));
        self::assertSame([0, 0], [$this->identifierHits(), $this->accountHits($identity)]);
    }

    /**
     * A sign-in held for a further factor has proven the password, so an
     * outdated hash is rehashed then, before the factor is verified, as for a
     * sign-in that starts its session at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordIsRehashedWhenItsSignInWaitsForAFactor(): void
    {
        $identity = $this->seedIdentity();
        $outdated = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 5]);

        IntegrationIdentity::query()->whereKey($identity->getKey())->update(['password' => $outdated]);

        $pending = $this->pendingFor();
        $stored  = IntegrationIdentity::query()->whereKey($identity->getKey())->value('password');

        self::assertIsString($stored);
        self::assertNotSame($outdated, $stored);
        self::assertFalse(app(Hasher::class)->needsRehash($stored));
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, $stored));
        self::assertSame(1, PendingSignIn::query()->count());
        self::assertSame(0, Device::query()->count());
        self::assertTrue($this->sessions()->complete($pending->token)->isSignedIn());
    }

    /**
     * Completion refuses a recorded membership that has since passed to another
     * member, even through a guard whose resolver looks the hint up by its key
     * alone: it fails as `pending_invalid` and starts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembershipThatPassedToAnotherMemberCannotBeCompleted(): void
    {
        config()->set('auth.guards.members.principal_resolver', UnscopedMembershipResolver::class);

        [, $membership, $tenant] = $this->seedMember();
        [$other]                 = $this->seedMember('other@example.test', $tenant);

        $pending = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->pending;

        self::assertNotNull($pending);

        $membership->forceFill(['identity_id' => $other->getKey()])->save();

        $this->recordEvents([AuthenticationFailed::class, SignedIn::class]);

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions('members')->complete($pending->token)->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(0, Device::query()->count());
    }

    /**
     * A pending sign-in whose factor failed is discarded: it is used up without
     * a session, whatever has changed about its identity since, and reported as
     * the failure of the sign-in that waited (`Failed`, then
     * `AuthenticationFailed` with `additional_factor_failed`, the method, the
     * discarding client and the identity, still returned though inactive); its
     * token then looks up and completes nothing. A token that names no live
     * pending sign-in of the guard discards nothing and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADiscardedPendingSignInCannotBeCompleted(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->pendingFor();
        $other    = $this->pendingFor();

        $identity->forceFill(['is_active' => false])->save();

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SignedIn::class]);

        self::assertFalse($this->sessions('admin')->discard($pending->token));
        self::assertFalse($this->sessions()->discard('not-a-pending-token'));
        self::assertFalse($this->sessions()->discard(explode('.', $pending->token, 2)[0] . '.wrong-secret'));
        self::assertSame([], $this->recordedClasses());
        self::assertTrue($this->completionGuard()->sessions()->discard($pending->token));
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::ADDITIONAL_FACTOR_FAILED, $failed->reason);
        self::assertSame('api', $failed->context->guard);
        self::assertSame('password', $failed->context->method);
        self::assertSame(self::COMPLETION_IP, $failed->context->client->ip);
        self::assertTrue($failed->context->identity instanceof IntegrationIdentity && $failed->context->identity->is($identity));
        self::assertNull($failed->context->principal);
        self::assertNull($failed->identifier);
        self::assertNull($failed->retryAfter);
        self::assertSame($failed->context->identity, $this->recordedEvent(Failed::class)->user);
        self::assertSame([], $this->recordedEvent(Failed::class)->credentials);

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SignedIn::class]);

        self::assertFalse($this->sessions()->discard($pending->token));
        self::assertSame([], $this->recordedClasses());
        self::assertNull($this->sessions()->pending($pending->token));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete($pending->token)->reason);
        self::assertSame(1, PendingSignIn::query()->count());

        $this->freezeClocksAt($this->now->addSeconds(300));

        self::assertFalse($this->sessions()->discard($other->token));
        self::assertSame(1, PendingSignIn::query()->count());
    }

    /**
     * A sign-in held for a further factor reports its outcome: after
     * `Attempting`, `AdditionalFactorRequired` with the guard, identity,
     * principal, method, client and expiry (and no tenant or device here), and
     * never the token; nothing that reports a session or a failure fires. A
     * `start()` held for a factor reports it too, without `Attempting`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInHeldForAFactorReportsIt(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([Attempting::class, AdditionalFactorRequired::class, Failed::class, AuthenticationFailed::class, Login::class, SignedIn::class]);

        $pending = $this->pendingFor(clientName: 'Phone');

        self::assertSame([Attempting::class, AdditionalFactorRequired::class], $this->recordedClasses());

        $required = $this->recordedEvent(AdditionalFactorRequired::class);

        self::assertSame('api', $required->context->guard);
        self::assertTrue($required->context->identity instanceof IntegrationIdentity && $required->context->identity->is($identity));
        self::assertSame($required->context->identity, $required->context->principal);
        self::assertNull($required->context->tenant);
        self::assertNull($required->context->device);
        self::assertSame('password', $required->context->method);
        self::assertSame(self::CLIENT_IP, $required->context->client->ip);
        self::assertSame($pending->expiresAt->getTimestamp(), $required->expiresAt->getTimestamp());
        self::assertStringNotContainsString(explode('.', $pending->token, 2)[1], serialize(get_object_vars($required)));

        $this->recordEvents([Attempting::class, AdditionalFactorRequired::class]);

        self::assertTrue($this->sessions()->start($identity, null, 'sso')->requiresFactor());
        self::assertSame([AdditionalFactorRequired::class], $this->recordedClasses());
        self::assertSame('sso', $this->recordedEvent(AdditionalFactorRequired::class)->context->method);
    }

    /**
     * A sign-in within a tenant carries the tenant through the factor seam: the
     * factor policy is told of it, `AdditionalFactorRequired` reports it, and
     * the completion's `DeviceCreated` and `SignedIn` carry it too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantReachesTheFactorPolicyAndEveryEvent(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $told    = [];
        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$told): bool {
            $told[] = $context->tenant?->getTenantIdentifier();

            return true;
        });

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $this->recordEvents([AdditionalFactorRequired::class, DeviceCreated::class, SignedIn::class]);

        $pending = $this->sessions('members')->start($member, null, 'sso')->pending;

        self::assertNotNull($pending);
        self::assertSame([$tenant->getKey()], $told);
        self::assertSame($tenant->getKey(), $this->recordedEvent(AdditionalFactorRequired::class)->context->tenant?->getTenantIdentifier());
        self::assertTrue($this->sessions('members')->complete($pending->token)->isSignedIn());
        self::assertSame($tenant->getKey(), $this->recordedEvent(DeviceCreated::class)->context->tenant?->getTenantIdentifier());
        self::assertSame($tenant->getKey(), $this->recordedEvent(SignedIn::class)->context->tenant?->getTenantIdentifier());
    }

    /**
     * `AdditionalFactorRequired` waits for the pending sign-in to commit:
     * inside a caller's transaction it fires on commit, and never when the
     * caller rolls the pending sign-in back. It names the device the client
     * proved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorRequestIsReportedOnlyOnceItsPendingSignInCommits(): void
    {
        $this->seedIdentity();

        $first = $this->signedInWithoutAFactor();

        $this->recordEvents([AdditionalFactorRequired::class]);

        DB::beginTransaction();

        $this->pendingFor();

        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, PendingSignIn::query()->count());

        DB::transaction(function () use ($first): void {

            $this->pendingFor(refreshToken: $first->tokens->refreshToken);

            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([AdditionalFactorRequired::class], $this->recordedClasses());
        self::assertSame($first->device->getKey(), $this->recordedEvent(AdditionalFactorRequired::class)->context->device?->getDeviceIdentifier());
    }

    /**
     * A pending sign-in keeps the attempt-limit slots its sign-in took: with
     * the password, five pending sign-ins whose factor failed use the
     * identifier's limit up, and the sixth sign-in is refused, so a further
     * factor can be guessed only as often as a password can. A completed
     * pending sign-in gives its slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFactorGuessesAreBoundedByTheSignInLimits(): void
    {
        $this->seedIdentity();

        $completed = $this->pendingFor();

        self::assertSame(1, $this->identifierHits());
        self::assertTrue($this->sessions()->complete($completed->token)->isSignedIn());
        self::assertSame(0, $this->identifierHits());

        for ($guess = 0; $guess < 5; $guess++) {
            self::assertTrue($this->sessions()->discard($this->pendingFor()->token));
        }

        $refused = $this->sessions()->signIn('password', self::credentials());

        self::assertSame(FailureReason::RATE_LIMITED, $refused->reason);
        self::assertSame(5, $this->identifierHits());
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * Only a completion that starts the session gives the slots back: one whose
     * recheck fails keeps the identifier's and the account's slots, and so does
     * one that loses the race for the pending sign-in, inside its transaction
     * or before it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedOrLostCompletionKeepsTheSlots(): void
    {
        $identity = $this->seedIdentity();
        $refused  = $this->pendingFor();

        $identity->forceFill(['is_active' => false])->save();

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->sessions()->complete($refused->token)->reason);
        self::assertSame([1, 1], [$this->identifierHits(), $this->accountHits($identity)]);

        $identity->forceFill(['is_active' => true])->save();

        $raced = $this->pendingFor();

        $this->onStatement('delete from', static function (): void {
            DB::table('pending_sign_ins')->delete();
        });

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete($raced->token)->reason);
        self::assertSame([2, 2], [$this->identifierHits(), $this->accountHits($identity)]);

        $completed = $this->pendingFor();

        self::assertTrue($this->sessions()->complete($completed->token)->isSignedIn());
        self::assertSame([2, 2], [$this->identifierHits(), $this->accountHits($identity)]);
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete($completed->token)->reason);
        self::assertSame([2, 2], [$this->identifierHits(), $this->accountHits($identity)]);
    }

    /**
     * A completed pending sign-in gives its slots back through whatever limiter
     * is bound, from the windows its sign-in's reservations recorded: one
     * reservation rebuilt for each it held (the identifier's and IP address's,
     * then the account's), for the guard's sign-in flow with the identifier
     * type and IP address but no identifier or account. A limiter that recorded
     * no windows is still told to give each back; a pending sign-in `start()`
     * issued reserved nothing and gives nothing back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletedPendingSignInGivesItsSlotsBackThroughAnyLimiter(): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        self::assertTrue($this->sessions()->complete($this->pendingFor()->token)->isSignedIn());
        self::assertCount(2, $limiter->released);

        $account = $limiter->acquired[1]->account;

        self::assertNotNull($account);
        self::assertSame([['ada@example.test' => 'window'], [$account => 'window']], array_map(static fn ($released): array => $released->windows, $limiter->released));

        foreach ($limiter->released as $released) {
            self::assertTrue($released->granted());
            self::assertSame('api', $released->subject->guard);
            self::assertSame(AttemptFlow::SIGN_IN, $released->subject->flow);
            self::assertNull($released->subject->identifier);
            self::assertSame('email', $released->subject->identifierType);
            self::assertSame(self::CLIENT_IP, $released->subject->ip);
            self::assertNull($released->subject->account);
        }

        $windowless = new RecordingAttemptLimiter(false);

        app()->instance(AttemptLimiter::class, $windowless);

        self::assertTrue($this->sessions()->complete($this->pendingFor()->token)->isSignedIn());
        self::assertCount(2, $windowless->released);
        self::assertSame([[], []], array_map(static fn ($released): array => $released->windows, $windowless->released));

        $started = $this->sessions()->start($identity, null, 'sso')->pending;

        self::assertNotNull($started);
        self::assertTrue($this->sessions()->complete($started->token)->isSignedIn());
        self::assertCount(2, $windowless->released);
    }

    /**
     * A method that checks two secrets counts two checks against the account,
     * and its pending sign-in, once completed, gives both slots back, as a
     * sign-in that starts its session at once does: completing further-factor
     * sign-ins never uses up the account's limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInGivesBackEverySlotItsMethodTookOnTheAccount(): void
    {
        $identity = $this->seedIdentity();
        $input    = [...self::credentials(), 'pin' => TwoSecretSignIn::PIN];

        app(SignInMethodManager::class)->extend('two_secrets', fn (): TwoSecretSignIn => new TwoSecretSignIn);
        config()->set('auth.guards.api.audience.methods', ['two_secrets']);

        for ($signIn = 1; $signIn <= 6; $signIn++) {

            $pending = $this->sessions()->signIn('two_secrets', $input)->pending;

            self::assertNotNull($pending);
            self::assertSame([1, 2], [$this->identifierHits(), $this->accountHits($identity)]);
            self::assertTrue($this->sessions()->complete($pending->token)->isSignedIn());
            self::assertSame([0, 0], [$this->identifierHits(), $this->accountHits($identity)]);
        }
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
     * Sign in and return the pending sign-in the factor policy asked for.
     *
     * @param  string  $method
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingFactor
     *
     * @throws \Throwable
     */
    private function pendingFor(
        string $method = 'password',
        ?string $clientName = null,
        ?string $platform = null,
        #[\SensitiveParameter] ?string $refreshToken = null,
    ): PendingFactor {
        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $clientName, $platform, null, $refreshToken);
        $result  = $this->sessions()->signIn($method, self::credentials(), $context);

        self::assertTrue($result->requiresFactor(), 'Expected a pending sign-in; got ' . $result->status->value);
        self::assertNotNull($result->pending);

        return $result->pending;
    }

    /**
     * Sign in with the factor policy asking for nothing, then require a factor
     * again.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedInWithoutAFactor(): SignedInSession
    {
        $factors = app(AdditionalFactorPolicy::class);

        app()->instance(AdditionalFactorPolicy::class, new NeverRequireAdditionalFactor);

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        app()->instance(AdditionalFactorPolicy::class, $factors);

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Assert that completing the pending sign-in fails with the reason, starts
     * nothing, and uses the pending sign-in up.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingFactor  $pending
     * @param  string  $guard
     * @return void
     *
     * @throws \Throwable
     */
    private function assertCompletionFails(FailureReason $reason, PendingFactor $pending, string $guard = 'api'): void
    {
        $devices = Device::query()->count();

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->sessions($guard)->complete($pending->token);

        self::assertSame($reason, $result->reason);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame($pending->method, $this->recordedEvent(AuthenticationFailed::class)->context->method);
        self::assertSame($devices, Device::query()->count());
        self::assertNull($this->sessions($guard)->pending($pending->token));
        self::assertSame(0, PendingSignIn::query()->whereKey(explode('.', $pending->token, 2)[0])->count());
    }

    /**
     * Bind a permissive audience policy mock whose expectations a test can add
     * to.
     *
     * @return \Mockery\MockInterface
     */
    private function audience(): MockInterface
    {
        $audience = \Mockery::mock(AudiencePolicy::class);
        $audience->shouldReceive('allowsMethod')->byDefault()->andReturnTrue();
        $audience->shouldReceive('admitIdentifier')->byDefault()->andReturnNull();
        $audience->shouldReceive('admit')->byDefault()->andReturnNull();
        $audience->shouldReceive('lifetimes')
            ->byDefault()
            ->andReturnUsing(static fn (string $guard): TokenLifetimes => app(JwtTokenServiceFactory::class)->forGuard($guard)->lifetimes());

        app()->instance(AudiencePolicy::class, $audience);

        return $audience;
    }

    /**
     * The hits on the `api` guard's sign-in counter for the seeded address.
     *
     * @return int
     */
    private function identifierHits(): int
    {
        return self::counterHits('api', 'sign_in', 'per_identifier', 'ada@example.test');
    }

    /**
     * The hits on the identity's account counter, which every guard shares.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return int
     */
    private function accountHits(IntegrationIdentity $identity): int
    {
        return self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity));
    }

    /**
     * Resolve the `api` guard for a completion request from another client.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function completionGuard(): JwtGuard
    {
        $guard = $this->freshGuard();

        $guard->setRequest(Request::create('/factor', 'POST', server: ['REMOTE_ADDR' => self::COMPLETION_IP]));

        return $guard;
    }

    /**
     * Run the callback once, just before the first statement on the default
     * connection that starts with the prefix.
     *
     * @param  string  $prefix
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function onStatement(string $prefix, \Closure $callback): void
    {
        $done = false;

        DB::connection()->beforeExecuting(static function (string $query) use ($prefix, $callback, &$done): void {

            if ($done || !str_starts_with(strtolower($query), $prefix)) {
                return;
            }

            $done = true;

            $callback();
        });
    }

    /**
     * Move both clocks to the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeClocksAt(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
