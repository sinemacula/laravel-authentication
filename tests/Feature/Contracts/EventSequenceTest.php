<?php

declare(strict_types = 1);

namespace Tests\Feature\Contracts;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoices;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Concerns\RecordsEventSequences;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Pins, for every authentication flow, the events it dispatches in order (with
 * the guard, the failure's flow and reason, and the identity, principal and
 * device of each) and what it answers: `attempt()`, `validate()`, `login()`,
 * `authenticateAs()`, a bearer token and an API key, the session service's
 * sign-ins and their continuations, refreshes, a switch of principal, signing
 * out, revocation on a security change, setting and resetting a password,
 * confirming a change of identifier, and the client credentials exchange.
 *
 * Each assertion records what the code does today: the behaviour the refactors
 * of the guard, its services and the session service must keep.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(ApiKeyGuard::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(PrincipalChoices::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(PasswordService::class)]
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ClientCredentialsExchange::class)]
final class EventSequenceTest extends TestCase
{
    use ChangesIdentifiers, InteractsWithMachineClients, InteractsWithPasswords, RecordsEventSequences;

    /** @var string The password a change or a reset sets. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();
        $this->createSessionTables();

        self::createPasswordTables();
        self::createMachineClientsTable();
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();
        self::dropPasswordTables();

        $this->dropSessionTables();
        $this->stopChanging();

        parent::tearDown();
    }

    /**
     * A successful `attempt()` binds as a sign-in and starts no session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulAttemptBindsAsASignInWithoutASession(): void
    {
        $identity = $this->seedIdentity();

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        self::assertTrue($guard->attempt(self::credentials()));
        self::assertSame([
            'Attempting api',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/-',
        ], $this->recordedSequence());
    }

    /**
     * A wrong password fails the attempt with the account it found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongPasswordFailsTheAttemptWithTheAccountItFound(): void
    {
        $identity = $this->seedIdentity();

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'wrong']));
        self::assertSame([
            'Attempting api',
            'Failed api i1',
            'AuthenticationFailed api sign_in:invalid_credentials -/-/-',
        ], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
    }

    /**
     * An attempt the factor policy asks a further factor of fails after the
     * credentials were validated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptThatNeedsAFurtherFactorFailsAfterValidating(): void
    {
        $identity = $this->seedIdentity();
        $this->requireAFurtherFactor();

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        self::assertFalse($guard->attempt(self::credentials()));
        self::assertSame([
            'Attempting api',
            'Validated api i1',
            'Failed api i1',
            'AuthenticationFailed api sign_in:additional_factor_required i1/p1/-',
        ], $this->recordedSequence());
    }

    /**
     * An attempt for an identity without a default principal fails after the
     * credentials were validated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptWithoutADefaultPrincipalFailsAfterValidating(): void
    {
        [$chooser] = $this->seedChooser();

        $guard = $this->freshGuard('choosers');

        $this->nameKeys($chooser, null);
        $this->recordSequence();

        self::assertFalse($guard->attempt(self::credentials('chooser@example.test')));
        self::assertSame([
            'Attempting choosers',
            'Validated choosers i1',
            'Failed choosers i1',
            'AuthenticationFailed choosers sign_in:principal_unresolved i1/-/-',
        ], $this->recordedSequence());
    }

    /**
     * An attempt over the identifier's limit fails before the credentials are
     * checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedAttemptFailsBeforeTheCredentialsAreChecked(): void
    {
        $this->seedIdentity();

        self::allowOneSignInAttempt();

        self::assertFalse($this->freshGuard()->attempt(['email' => 'ada@example.test', 'password' => 'wrong']));

        $guard = $this->freshGuard();

        $this->recordSequence();

        self::assertFalse($guard->attempt(self::credentials()));
        self::assertSame([
            'Attempting api',
            'Failed api -',
            'AuthenticationFailed api sign_in:rate_limited -/-/-',
        ], $this->recordedSequence());
    }

    /**
     * `validate()` reports only credentials it accepts, and binds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValidateReportsOnlyCredentialsItAccepts(): void
    {
        $identity = $this->seedIdentity();

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        self::assertFalse($guard->validate(['email' => 'ada@example.test', 'password' => 'wrong']));
        self::assertTrue($guard->validate(self::credentials()));
        self::assertSame(['Validated api i1'], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
    }

    /**
     * `login()` binds as a sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLoginBindsAsASignIn(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->signedIn()->device;

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity, $device);
        $this->recordSequence();

        $guard->login($identity, $identity, $device);

        self::assertSame([
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * `authenticateAs()` binds as an authentication, not a sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAuthenticateAsBindsWithoutASignIn(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->signedIn()->device;

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity, $device);
        $this->recordSequence();

        $guard->authenticateAs($identity, $identity, $device);

        self::assertSame([
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * A request's bearer token authenticates it without a sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerTokenAuthenticatesWithoutASignIn(): void
    {
        $identity = $this->seedIdentity();

        $session = $this->signedIn();

        $this->nameKeys($identity, $identity, $session->device);
        $this->recordSequence();

        self::assertNotNull($this->bearerGuard($session->tokens->accessToken)->user());
        self::assertSame([
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * A rejected bearer token is reported once, with its reason only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARejectedBearerTokenIsReportedOnceWithItsReason(): void
    {
        $guard = $this->bearerGuard('not-a-token');

        $this->recordSequence();

        self::assertNull($guard->user());
        self::assertNull($guard->user());
        self::assertSame(['AuthenticationFailed api bearer:token_invalid -/-/-'], $this->recordedSequence());
    }

    /**
     * An API key authenticates its owner as its principal, with no device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApiKeyAuthenticatesItsOwnerWithoutADevice(): void
    {
        $machine  = MachineClient::query()->create(['email' => 'robot@example.test']);
        $key      = $this->keys()->issue($machine, $machine, ['reports'])->key();
        $tampered = substr($key, 0, -1) . (str_ends_with($key, 'x') ? 'y' : 'x');

        $this->nameKeys($machine, $machine);
        $this->recordSequence();

        self::assertNotNull($this->bearerGuard($key, 'keys')->user());
        self::assertNull($this->bearerGuard($tampered, 'keys')->user());
        self::assertSame([
            'Authenticated keys i1',
            'PrincipalAssigned keys i1/p1/-',
            'AuthenticationFailed keys api_key:credential_invalid -/-/-',
        ], $this->recordedSequence());
    }

    /**
     * A sign-in on a new device reports the device and the session before it
     * binds as a sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInReportsItsNewDeviceAndSessionBeforeTheBind(): void
    {
        $identity = $this->seedIdentity();

        $sessions = $this->sessions();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        $result = $sessions->signIn('password', self::credentials());

        self::assertSame(SignInStatus::SIGNED_IN, $result->status);
        self::assertSame([
            'Attempting api',
            'DeviceCreated api i1/p1/d1',
            'SignedIn api new i1/p1/d1',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
        self::assertSame('d1', $this->nameOfSessionDevice($result));
    }

    /**
     * A sign-in whose client proves the device it holds continues it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInThatProvesItsDeviceContinuesIt(): void
    {
        $identity = $this->seedIdentity();

        $first    = $this->signedIn();
        $sessions = $this->sessions();
        $context  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken);

        $this->nameKeys($identity, $identity, $first->device);
        $this->recordSequence();

        $result = $sessions->signIn('password', self::credentials(), $context);

        self::assertTrue($first->device->is($result->session?->device));
        self::assertSame([
            'Attempting api',
            'SignedIn api continued i1/p1/d1',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * A sign-in held for a further factor reports the request and binds
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInHeldForAFurtherFactorBindsNothing(): void
    {
        $identity = $this->seedIdentity();
        $this->requireAFurtherFactor();

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        $result = self::sessionsOf($guard)->signIn('password', self::credentials());

        self::assertSame(SignInStatus::FACTOR_REQUIRED, $result->status);
        self::assertSame([
            'Attempting api',
            'AdditionalFactorRequired api i1/p1/-',
        ], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
    }

    /**
     * A sign-in held for a choice of principal reports the choice and binds
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInHeldForAChoiceOfPrincipalBindsNothing(): void
    {
        [$chooser] = $this->seedChooser();

        $guard = $this->freshGuard('choosers');

        $this->nameKeys($chooser, null);
        $this->recordSequence();

        $result = self::sessionsOf($guard)->signIn('password', self::credentials('chooser@example.test'));

        self::assertSame(SignInStatus::PRINCIPAL_REQUIRED, $result->status);
        self::assertSame([
            'Attempting choosers',
            'PrincipalChoiceRequired choosers i1/-/-',
        ], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
    }

    /**
     * A sign-in over the identifier's limit fails before the credentials are
     * checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedSignInFailsBeforeTheCredentialsAreChecked(): void
    {
        $this->seedIdentity();

        self::allowOneSignInAttempt();

        self::assertTrue($this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'])->isFailed());

        $sessions = $this->sessions();

        $this->recordSequence();

        $result = $sessions->signIn('password', self::credentials());

        self::assertSame([FailureReason::RATE_LIMITED, true], [$result->reason, $result->retryAfter > 0]);
        self::assertSame([
            'Attempting api',
            'Failed api -',
            'AuthenticationFailed api sign_in:rate_limited -/-/-',
        ], $this->recordedSequence());
    }

    /**
     * `start()` reports the session and binds as a sign-in, without
     * `Attempting`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartSignsInWithoutAttempting(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        $result = $sessions->start($identity, null, 'sso');

        self::assertTrue($result->isSignedIn());
        self::assertSame([
            'DeviceCreated api i1/p1/d1',
            'SignedIn api new i1/p1/d1',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
        self::assertSame('d1', $this->nameOfSessionDevice($result));
    }

    /**
     * `complete()` starts the held sign-in's session as a sign-in does, without
     * `Attempting`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompleteSignsInWithoutAttempting(): void
    {
        $identity = $this->seedIdentity();
        $this->requireAFurtherFactor();

        $token    = $this->sessions()->signIn('password', self::credentials())->pending?->token;
        $sessions = $this->sessions();

        self::assertIsString($token);

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        $result = $sessions->complete($token);

        self::assertTrue($result->isSignedIn());
        self::assertSame([
            'DeviceCreated api i1/p1/d1',
            'SignedIn api new i1/p1/d1',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
        self::assertSame('d1', $this->nameOfSessionDevice($result));
    }

    /**
     * `choose()` starts the session as the chosen principal, as a sign-in does,
     * without `Attempting`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChooseSignsInAsTheChosenPrincipal(): void
    {
        [$chooser, $membership] = $this->seedChooser();

        $token    = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'))->choice?->token;
        $sessions = $this->sessions('choosers');

        self::assertIsString($token);

        $this->nameKeys($chooser, $membership);
        $this->recordSequence();

        $result = $sessions->choose($token, $membership);

        self::assertTrue($chooser->is($result->session?->identity));
        self::assertSame([
            'DeviceCreated choosers i1/p1/d1',
            'SignedIn choosers new i1/p1/d1',
            'Validated choosers i1',
            'Login choosers i1',
            'Authenticated choosers i1',
            'PrincipalAssigned choosers i1/p1/d1',
            'DeviceAuthenticated choosers i1/p1/d1',
        ], $this->recordedSequence());
        self::assertSame('d1', $this->nameOfSessionDevice($result));
    }

    /**
     * `discard()` reports the held sign-in's failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDiscardReportsTheHeldSignInsFailureOnce(): void
    {
        $identity = $this->seedIdentity();
        $this->requireAFurtherFactor();

        $token    = $this->sessions()->signIn('password', self::credentials())->pending?->token;
        $sessions = $this->sessions();

        self::assertIsString($token);

        $this->nameKeys($identity, $identity);
        $this->recordSequence();

        self::assertTrue($sessions->discard($token));
        self::assertFalse($sessions->discard($token));
        self::assertSame([
            'Failed api i1',
            'AuthenticationFailed api sign_in:additional_factor_failed i1/-/-',
        ], $this->recordedSequence());
    }

    /**
     * A refresh reports the rotation and the session before it binds as a
     * sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshReportsTheRotationBeforeTheBind(): void
    {
        $identity = $this->seedIdentity();

        $session = $this->signedIn();
        $refresh = $session->tokens->refreshToken;
        $guard   = $this->freshGuard();

        $this->nameKeys($identity, $identity, $session->device);
        $this->recordSequence();

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($refresh));
        self::assertSame([
            'Attempting api',
            'Refreshed api i1/p1/d1',
            'SignedIn api refresh i1/p1/d1',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * A refresh with the token the request carries reports as a refresh does,
     * one its transport refuses as a failed refresh, and a request without one
     * dispatches nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshFromTheRequestReportsAsARefreshDoes(): void
    {
        $identity = $this->seedIdentity();

        $session = $this->signedIn();
        $refresh = $session->tokens->refreshToken;

        $this->nameKeys($identity, $identity, $session->device);
        $this->recordSequence();

        self::assertNull($this->freshGuard()->refreshFromRequest());
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $this->refreshGuard(['HTTP_X_REFRESH_TOKEN' => $refresh], ['refresh_token' => $refresh])->refreshFromRequest());
        self::assertInstanceOf(RefreshResult::class, $this->refreshGuard(['HTTP_X_REFRESH_TOKEN' => $refresh])->refreshFromRequest());
        self::assertSame([
            'Attempting api',
            'Failed api -',
            'AuthenticationFailed api refresh:refresh_token_conflict -/-/-',
            'Attempting api',
            'Refreshed api i1/p1/d1',
            'SignedIn api refresh i1/p1/d1',
            'Validated api i1',
            'Login api i1',
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * A refresh token replayed after its grace window revokes the device and
     * fails the refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplayedRefreshTokenRevokesTheDevice(): void
    {
        $identity = $this->seedIdentity();

        $session = $this->signedIn();
        $device  = $session->device;
        $refresh = $session->tokens->refreshToken;

        self::assertNotNull($this->freshGuard()->refresh($refresh));

        $this->moveTo($this->now->addMinute());

        $guard = $this->freshGuard();

        $this->nameKeys($identity, $identity, $device);
        $this->recordSequence();

        self::assertNull($guard->refresh($refresh));
        self::assertSame('rotation_reuse', $device->fresh()?->getRevokedReason());
        self::assertSame([
            'Attempting api',
            'DeviceRevoked api rotation_reuse i1/p1/d1',
            'Failed api -',
            'AuthenticationFailed api refresh:rotation_reuse i1/p1/d1',
        ], $this->recordedSequence());
    }

    /**
     * A refresh over the client's limit is reported and answered with a 429.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedRefreshIsReportedAndThrottled(): void
    {
        config()->set('authentication.rate_limits.refresh.per_ip.max', 1);

        self::assertNull($this->freshGuard()->refresh('not-a-token'));

        $guard = $this->freshGuard();

        $this->recordSequence();

        try {
            $guard->refresh('not-a-token');
            self::fail('Expected the refresh to be throttled.');
        } catch (ThrottleRequestsException $exception) {
            self::assertSame(429, $exception->getStatusCode());
        }

        self::assertSame([
            'Attempting api',
            'Failed api -',
            'AuthenticationFailed api refresh:rate_limited -/-/-',
        ], $this->recordedSequence());
    }

    /**
     * A switch of principal reports the switch and binds as an authentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsReportedAndBindsWithoutASignIn(): void
    {
        [$member, $first] = $this->seedMember();

        $tenant  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->signedIn('members', 'member@example.test');

        $sessions = $this->sessions('members');

        $this->nameKeys($member, $first, $session->device);
        $this->namePrincipals($second);
        $this->recordSequence();

        self::assertTrue($sessions->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());
        self::assertSame([
            'PrincipalSwitched members from:p1 i1/p2/d1',
            'Authenticated members i1',
            'PrincipalAssigned members i1/p2/d1',
            'DeviceAuthenticated members i1/p2/d1',
        ], $this->recordedSequence());
    }

    /**
     * Signing out revokes the bound device and then reports the sign-out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutRevokesTheDeviceBeforeTheLogout(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->signedIn()->device;
        $guard    = $this->freshGuard();

        $guard->login($identity, $identity, $device);

        $this->nameKeys($identity, $identity, $device);
        $this->recordSequence();

        self::assertTrue(self::sessionsOf($guard)->signOut());
        self::assertSame([
            'DeviceRevoked api signed_out i1/p1/d1',
            'Logout api i1',
        ], $this->recordedSequence());
        self::assertFalse($guard->hasUser());
    }

    /**
     * The guard's `logout()` resolves the request's token and signs its session
     * out as the session service does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLogoutSignsTheRequestsSessionOut(): void
    {
        $identity = $this->seedIdentity();

        $session = $this->signedIn();
        $guard   = $this->bearerGuard($session->tokens->accessToken);

        $this->nameKeys($identity, $identity, $session->device);
        $this->recordSequence();

        $guard->logout();

        self::assertSame([
            'Authenticated api i1',
            'PrincipalAssigned api i1/p1/d1',
            'DeviceAuthenticated api i1/p1/d1',
            'DeviceRevoked api signed_out i1/p1/d1',
            'Logout api i1',
        ], $this->recordedSequence());
        self::assertNull($guard->user());
    }

    /**
     * Signing out everywhere else revokes the identity's other devices and then
     * reports the sign-out everywhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutEverywhereElseRevokesTheOtherDevices(): void
    {
        $identity = $this->seedIdentity();
        $current  = $this->signedIn()->device;

        $this->nameKeys($identity, $identity, $current, $this->signedIn()->device);

        $guard = $this->freshGuard();

        $guard->login($identity, $identity, $current);

        $this->recordSequence();

        self::assertSame(1, self::sessionsOf($guard)->signOutEverywhere(true));
        self::assertSame([
            'DeviceRevoked api signed_out_everywhere i1/p1/d2',
            'SignedOutEverywhere api signed_out_everywhere:1 i1/-/d1',
        ], $this->recordedSequence());
        self::assertTrue($guard->hasUser());
    }

    /**
     * A security change (here a changed password) revokes each session of the
     * identity and then reports the sign-out everywhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASecurityChangeRevokesEachSessionThenReportsIt(): void
    {
        $identity = $this->seedIdentity();

        $this->nameKeys($identity, $identity, $this->signedIn()->device, $this->signedIn()->device);

        $sessions = $this->sessions();

        $this->recordSequence();

        self::assertSame(2, $sessions->passwordChanged($identity));
        self::assertSame([
            'DeviceRevoked api password_changed i1/p1/d1',
            'DeviceRevoked api password_changed i1/p1/d2',
            'SignedOutEverywhere api password_changed:2 i1/-/-',
        ], $this->recordedSequence());
    }

    /**
     * Setting a changed password ends the identity's other sessions and then
     * reports the password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSettingAPasswordEndsTheOtherSessionsFirst(): void
    {
        $identity = self::seedPasswordIdentity();
        $current  = $this->signInWithPassword()->device;

        $this->nameKeys($identity, $identity, $current, $this->signInWithPassword()->device);
        $this->freshGuard('web');

        $this->recordSequence();

        $result = Auth::passwords('web')->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE, $current);

        self::assertTrue($result->isSet());
        self::assertSame([
            'DeviceRevoked web password_changed i1/p1/d2',
            'SignedOutEverywhere web password_changed:1 i1/-/d1',
            'PasswordSet web change i1/-/d1',
        ], $this->recordedSequence());
    }

    /**
     * Resetting a password ends every session of the identity and then reports
     * the password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResettingAPasswordEndsEverySessionFirst(): void
    {
        $identity = self::seedPasswordIdentity();

        $this->nameKeys($identity, $identity, $this->signInWithPassword()->device);

        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('web', 'email', 'ada@example.test'), CarbonImmutable::now(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        $this->freshGuard('web');
        $this->recordSequence();

        $result = Auth::passwords('web')->reset(['email' => 'ada@example.test', 'token' => $issued->code, 'password' => self::NEW_PASSWORD]);

        self::assertSame([ResetStatus::RESET, 1], [$result->status, $result->revoked]);
        self::assertSame([
            'DeviceRevoked web password_reset i1/p1/d1',
            'SignedOutEverywhere web password_reset:1 i1/-/-',
            'PasswordSet web reset i1/-/-',
        ], $this->recordedSequence());
    }

    /**
     * A change of identifier is reported when it is requested and when it is
     * confirmed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeOfIdentifierIsReportedWhenRequestedAndConfirmed(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);

        $this->nameKeys($identity, null);
        $this->recordSequence();

        self::assertTrue($this->changes('changes')->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes('changes')->confirmByCode($identity, 'email', self::CODE));
        self::assertSame([
            'IdentifierChangeRequested changes i1/-/-',
            'IdentifierChanged changes i1/-/-',
        ], $this->recordedSequence());
    }

    /**
     * The client credentials exchange reports a grant, and a refused secret
     * with its reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientCredentialsExchangeReportsItsGrantAndItsRefusal(): void
    {
        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);
        $issued  = $this->keys('m2m')->issue($machine, $machine, ['reports']);

        $this->freshGuard('m2m');
        $this->nameKeys($machine, $machine);
        $this->recordSequence();

        self::assertTrue(Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, substr($issued->key(), 20))->isGranted());
        self::assertFalse(Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, 'wrong')->isGranted());
        self::assertSame([
            'ClientCredentialsGranted m2m i1/p1/-',
            'AuthenticationFailed m2m client_credentials:credential_invalid -/-/-',
        ], $this->recordedSequence());
    }

    /**
     * Register the guards: the session tests', the password tests', one over
     * members who must choose a principal, one over identities whose
     * identifiers change, an API key guard and a client credentials guard over
     * machine clients.
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
        self::configurePasswordGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.providers.changeables', ['driver' => 'model', 'model' => ChangeableIdentity::class]);
        $config->set('auth.providers.machine_clients', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
        $config->set('auth.guards.changes', ['driver' => 'jwt', 'provider' => 'changeables', 'audience' => ['methods' => ['password', 'email_code']]]);
        $config->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'machine_clients', 'audience' => ['methods' => ['api_key']]]);
        $config->set('auth.guards.m2m', ['driver' => 'jwt', 'provider' => 'machine_clients', 'audience' => ['methods' => ['client_credentials']]]);
    }

    /**
     * Seed a member of two tenants, who has no default principal: the member
     * and the first membership.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $chooser     = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $chooser->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$chooser, $memberships[0]];
    }

    /**
     * Name the identity `i1`, the principal `p1` and the devices `d1`, `d2`,
     * ... in the order given, before any event names them.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  ?\Illuminate\Database\Eloquent\Model  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  ...$devices
     * @return void
     */
    private function nameKeys(Model $identity, ?Model $principal, Device ...$devices): void
    {
        $this->nameIdentities($identity);
        $this->namePrincipals(...array_filter([$principal]));
        $this->nameDevices(...$devices);
    }

    /**
     * The name of the device the result's session was started on.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return string
     */
    private function nameOfSessionDevice(SignInResult $result): string
    {
        self::assertNotNull($result->session);

        return $this->nameOfDevice($result->session->device);
    }

    /**
     * Sign in through the guard's password method, as a fresh request, and
     * return the session.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Start a request carrying the bearer credential and resolve the guard
     * afresh for it.
     *
     * @param  string  $credential
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function bearerGuard(string $credential, string $guard = 'api'): AbstractGuard
    {
        self::startRequest(['HTTP_AUTHORIZATION' => 'Bearer ' . $credential]);

        $resolved = app('auth')->guard($guard);

        self::assertInstanceOf(AbstractGuard::class, $resolved);

        return $resolved;
    }

    /**
     * Start a request with the server values and body and resolve the `api`
     * guard afresh for it.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function refreshGuard(array $server, array $body = []): JwtGuard
    {
        self::startRequest($server, $body);

        $resolved = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $resolved);

        return $resolved;
    }

    /**
     * Start a request from the test client with the server values and body, and
     * forget the resolved guards.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @return void
     */
    private static function startRequest(array $server, array $body = []): void
    {
        app()->instance('request', Request::create('/', 'POST', $body, server: ['REMOTE_ADDR' => self::CLIENT_IP, 'HTTP_USER_AGENT' => self::CLIENT_AGENT, ...$server]));

        Auth::forgetGuards();
    }

    /**
     * The API keys of the guard, on a fresh request.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService
     */
    private function keys(string $guard = 'keys'): ApiKeyService
    {
        $this->freshGuard('api');

        return Auth::apiKeys($guard);
    }

    /**
     * Have the factor policy ask every sign-in for a further factor.
     *
     * @return void
     */
    private function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
    }

    /**
     * Allow each identifier one sign-in attempt.
     *
     * @return void
     */
    private static function allowOneSignInAttempt(): void
    {
        config()->set('authentication.rate_limits.sign_in.per_identifier.max', 1);
    }
}
