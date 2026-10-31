<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyOwner;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for usernameless sign-in with a passkey through the session
 * service: what starts a session, and how each refusal is reported to the
 * client and to listeners.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeySignIn::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(PasskeyCredentials::class)]
#[CoversClass(PasskeyOwner::class)]
final class PasskeySignInTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

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

        self::freezeAt($this->now);

        $this->createSessionTables();
    }

    /**
     * Drop the tables and release the clocks.
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
     * The method is registered as `passkey` and names no identifier, so the
     * sign-in is usernameless.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheMethodIsUsernameless(): void
    {
        $method = app(SignInMethodManager::class)->method('passkey');

        self::assertInstanceOf(PasskeySignIn::class, $method);
        self::assertNull($method->identifierType('api'));
        self::assertNull($method->identifier('api', ['challenge' => 'x', 'credential' => [], 'email' => 'ada@example.test']));
    }

    /**
     * A passkey's assertion signs its owner in on a new device recorded as a
     * `passkey` sign-in with no identifier type; the passkey records the new
     * count and its use, `PasskeyUsed` reports it with the passkey's id before
     * `SignedIn`, the challenge is used up, and `Attempting` names no
     * identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeySignsItsOwnerIn(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        $this->recordEvents([Attempting::class, PasskeyUsed::class, SignedIn::class]);

        $result = $this->signInWithPasskey();

        self::assertTrue($result->isSignedIn());
        self::assertTrue($identity->is($result->session?->identity));
        self::assertSame([Attempting::class, PasskeyUsed::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([], $this->recordedEvent(Attempting::class)->credentials);

        $used = $this->recordedEvent(PasskeyUsed::class);

        self::assertSame(['api', 'passkey'], [$used->context->guard, $used->context->method]);
        self::assertSame([$passkey->id, (string) $identity->id], [$used->context->credentialId, $used->context->identityId]);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$used->context->client->ip, $used->context->client->userAgent]);

        $device = Device::query()->sole();

        self::assertSame(['passkey', null], [$device->sign_in_method, $device->sign_in_identifier_type]);

        $stored = Passkey::query()->sole();

        self::assertSame(1, $stored->sign_count);
        self::assertTrue($stored->last_used_at?->equalTo($this->now));
        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * A sign-in's `PasskeyUsed` goes, once committed, to the dispatcher bound
     * when the commit runs it, as its `SignedIn` does: one bound after the
     * sign-in, before the caller commits, receives both, and the dispatcher
     * bound when the sign-in was made receives neither.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseReachesTheDispatcherBoundAtTheCommit(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $rebound  = new Dispatcher(app());
        $received = [];

        $rebound->listen([PasskeyUsed::class, SignedIn::class], static function (object $event) use (&$received): void {
            $received[] = $event::class;
        });

        $this->recordEvents([PasskeyUsed::class, SignedIn::class]);

        DB::transaction(function () use ($rebound): void {
            self::assertTrue($this->signInWithPasskey()->isSignedIn());

            app()->instance('events', $rebound);
        });

        self::assertSame([], $this->recordedClasses());
        self::assertSame([PasskeyUsed::class, SignedIn::class], $received);
    }

    /**
     * The browser's response is accepted as JSON as well as decoded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheResponseIsAcceptedAsJson(): void
    {
        $this->registerPasskey($this->seedIdentity());

        self::assertTrue($this->signInWithPasskey(tamper: static fn (array $credential): string => (string) json_encode($credential))->isSignedIn());
    }

    /**
     * Rows of `[challenge]`: challenges a sign-in through `api` cannot answer,
     * each made by the closure, or input without one.
     *
     * @return iterable<string, array{0: \Closure(self): mixed}>
     */
    public static function provideInvalidChallenges(): iterable
    {
        yield from [
            'none'              => [static fn (): mixed => null],
            'not a string'      => [static fn (): mixed => ['0192f6b2-0000-7000-8000-000000000001']],
            'not a UUID'        => [static fn (): mixed => 'challenge'],
            'an unknown id'     => [static fn (): mixed => '0192f6b2-0000-7000-8000-000000000001'],
            'another guard\'s'  => [static fn (): mixed => Auth::passkeys('admin')->signInOptions()->challengeId],
            'a registration\'s' => [static fn (self $test): mixed => Auth::passkeys('api')->registrationOptions(IntegrationIdentity::query()->firstOrFail(), 'ada')->challengeId],
            'a factor\'s'       => [static fn (self $test): mixed => Auth::passkeys('api')->factorOptions(IntegrationIdentity::query()->firstOrFail())->challengeId],
        ];
    }

    /**
     * A sign-in that answers no live sign-in challenge of the guard fails as
     * `passkey_challenge_invalid`, in its result as in its event, since it says
     * nothing about any account; the passkey is not touched.
     *
     * @param  \Closure(self): mixed  $challenge
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideInvalidChallenges')]
    public function testASignInThatAnswersNoChallengeOfTheGuardFails(\Closure $challenge): void
    {
        $this->registerPasskey($this->seedIdentity());

        $id         = $challenge($this);
        $credential = $this->authenticator()->get($this->signInOptions()->options);

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $result = $this->sessions()->signIn('passkey', ['challenge' => $id, 'credential' => $credential]);

        $this->assertFailed($result, FailureReason::PASSKEY_CHALLENGE_INVALID, FailureReason::PASSKEY_CHALLENGE_INVALID);
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * A challenge answers one sign-in: the same answer again fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeAnswersOneSignIn(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $options = $this->signInOptions();
        $input   = ['challenge' => $options->challengeId, 'credential' => $this->authenticator()->get($options->options)];

        self::assertTrue($this->sessions()->signIn('passkey', $input)->isSignedIn());
        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, $this->sessions()->signIn('passkey', $input)->reason);
    }

    /**
     * A challenge answered at or after its expiry is refused; one answered the
     * second before is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredChallengeIsRefused(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $live    = $this->signInOptions();
        $expired = $this->signInOptions();

        self::freezeAt($this->now->addSeconds(299));

        self::assertTrue($this->sessions()->signIn('passkey', ['challenge' => $live->challengeId, 'credential' => $this->authenticator()->get($live->options)])->isSignedIn());

        self::freezeAt($this->now->addSeconds(300));

        $result = $this->sessions()->signIn('passkey', ['challenge' => $expired->challengeId, 'credential' => $this->authenticator()->get($expired->options)]);

        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, $result->reason);
    }

    /**
     * Rows of `[credential]`: input that carries no well-formed response.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedCredentials(): iterable
    {
        yield from [
            'none'              => [null],
            'not an array'      => [42],
            'not JSON'          => ['{"id"'],
            'an empty response' => [[]],
        ];
    }

    /**
     * A sign-in without a well-formed response fails as `invalid_credentials`
     * and uses its challenge up.
     *
     * @param  mixed  $credential
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedCredentials')]
    public function testAMalformedResponseFails(mixed $credential): void
    {
        $this->registerPasskey($this->seedIdentity());

        $options = $this->signInOptions();

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $result = $this->sessions()->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $credential]);

        $this->assertFailed($result, FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS);
        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * A credential that is registered nowhere fails as `invalid_credentials`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownCredentialFails(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $stranger = new VirtualAuthenticator(self::ORIGIN);

        $stranger->create(['rp' => ['id' => self::RP_ID], 'user' => ['id' => VirtualAuthenticator::encode('handle')], 'challenge' => 'challenge']);

        $options = $this->signInOptions();

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $result = $this->sessions()->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $stranger->get($options->options)]);

        $this->assertFailed($result, FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS);
    }

    /**
     * A passkey registered for another relying party is not one of this
     * guard's, even with an origin both accept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyOfAnotherRelyingPartyFails(): void
    {
        config()->set('auth.guards.admin.passkeys', ['id' => 'app.example.test']);

        $this->registerPasskey($this->seedIdentity(), 'admin');

        $options    = $this->signInOptions();
        $credential = $this->authenticator()->get(['rpId' => 'app.example.test'] + $options->options);

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $result = $this->sessions()->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $credential]);

        $this->assertFailed($result, FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS);
    }

    /**
     * A passkey whose owner the guard's provider does not return as that very
     * model fails, even when the provider holds a model of another class under
     * the same key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyWhoseOwnerTheProviderDoesNotReturnFails(): void
    {
        $identity = $this->seedIdentity();

        [$member] = $this->seedMember();

        self::assertSame($identity->id, $member->getKey());

        $this->registerPasskey($identity);

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $this->assertFailed($this->signInWithPasskey('members'), FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS);
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * Rows of `[fault]`: assertions that do not verify.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Fixtures\Passkeys\VirtualAuthenticator): void, 1: ?\Closure(array<string, mixed>): array<string, mixed>}>
     */
    public static function provideUnverifiedAssertions(): iterable
    {
        yield from [
            'a forged signature'   => [static function (): void {}, static fn (array $credential): array => self::withResponse($credential, 'signature', 'Zm9yZ2Vk')],
            'another user handle'  => [static function (): void {}, static fn (array $credential): array => self::withResponse($credential, 'userHandle', 'b3RoZXI')],
            'no user handle'       => [static function (): void {}, static fn (array $credential): array => self::withResponse($credential, 'userHandle', null)],
            'no user verification' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->userVerified = false;
            }, null],
            'another origin' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->origin = 'https://evil.test';
            }, null],
            'a subdomain of the origin' => [static function (VirtualAuthenticator $authenticator): void {
                $authenticator->origin = 'https://deep.app.example.test';
            }, null],
        ];
    }

    /**
     * An assertion that does not verify fails as `invalid_credentials`, and
     * leaves the passkey as it was.
     *
     * @param  \Closure(\Tests\Fixtures\Passkeys\VirtualAuthenticator): void  $fault
     * @param  ?\Closure(array<string, mixed>): array<string, mixed>  $tamper
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnverifiedAssertions')]
    public function testAnAssertionThatDoesNotVerifyFails(\Closure $fault, ?\Closure $tamper): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $fault($this->authenticator());

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $this->assertFailed($this->signInWithPasskey(tamper: $tamper), FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS);
        self::assertSame([0, null], [Passkey::query()->sole()->sign_count, Passkey::query()->sole()->last_used_at]);
    }

    /**
     * An assertion whose count does not advance, as a clone's would not, fails:
     * the result conceals it as `invalid_credentials`, the event says
     * `passkey_counter_regressed`, and the passkey keeps its count, so the
     * genuine authenticator still signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACountThatDoesNotAdvanceFailsAndIsConcealed(): void
    {
        $this->registerPasskey($this->seedIdentity());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        $this->authenticator()->setCounter($this->authenticator()->lastCredentialId(), 0);

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $this->assertFailed($this->signInWithPasskey(), FailureReason::INVALID_CREDENTIALS, FailureReason::PASSKEY_COUNTER_REGRESSED);
        self::assertSame(1, Passkey::query()->sole()->sign_count);

        $this->authenticator()->setCounter($this->authenticator()->lastCredentialId(), 1);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame(2, Passkey::query()->sole()->sign_count);
    }

    /**
     * An authenticator without a counter (a synced passkey) signs in again and
     * again with a count of 0, which stays 0.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAuthenticatorWithoutACounterSignsInRepeatedly(): void
    {
        $this->authenticator()->counterStep = 0;

        $this->registerPasskey($this->seedIdentity());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * Rows of `[counter step, change]`: what happens to the passkey, made by
     * the closure, after the sign-in found it and before it records the use.
     *
     * @return iterable<string, array{0: int, 1: \Closure(): mixed}>
     */
    public static function provideChangesBeforeTheUse(): iterable
    {
        yield from [
            'a passkey without a counter is removed' => [0, static fn (): mixed => Passkey::query()->delete()],
            'a counting passkey is removed'          => [1, static fn (): mixed => Passkey::query()->delete()],
            'another use records the same count'     => [1, static fn (): mixed => Passkey::query()->update(['sign_count' => 1])],
        ];
    }

    /**
     * A passkey removed, or whose count another use recorded first, while its
     * sign-in was between finding it and recording the use signs nobody in,
     * whether or not its authenticator counts: `invalid_credentials`, with
     * `passkey_counter_regressed` on the event, and no use reported.
     *
     * @param  int  $step
     * @param  \Closure(): mixed  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesBeforeTheUse')]
    public function testAPasskeyChangedBeforeItsUseIsRecordedSignsNobodyIn(int $step, \Closure $change): void
    {
        $this->authenticator()->counterStep = $step;

        $this->registerPasskey($this->seedIdentity());

        IntegrationIdentity::retrieved(static function () use ($change): void {
            $change();
        });

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class, SignedIn::class]);

        $this->assertFailed($this->signInWithPasskey(), FailureReason::INVALID_CREDENTIALS, FailureReason::PASSKEY_COUNTER_REGRESSED);
        self::assertSame(0, Device::query()->count());
    }

    /**
     * Once the owner's account has used up its attempts, a passkey's assertion
     * is not checked: the result says `invalid_credentials`, the event
     * `account_rate_limited` with the wait, and the passkey is not touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccountWithNoAttemptsLeftIsNotChecked(): void
    {
        config()->set('authentication.rate_limits.sign_in.per_identifier', ['max' => 2, 'decay_seconds' => 300]);

        $this->registerPasskey($this->seedIdentity());

        $forged = static fn (array $credential): array => self::withResponse($credential, 'signature', VirtualAuthenticator::encode('forged'));

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signInWithPasskey(tamper: $forged)->reason);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signInWithPasskey(tamper: $forged)->reason);

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $result = $this->signInWithPasskey();

        $this->assertFailed($result, FailureReason::INVALID_CREDENTIALS, FailureReason::ACCOUNT_RATE_LIMITED);
        self::assertNull($result->retryAfter);
        self::assertSame(300, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * A successful sign-in gives its account slot back, so the account's limit
     * counts only failures.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInGivesItsAccountSlotBack(): void
    {
        config()->set('authentication.rate_limits.sign_in.per_identifier', ['max' => 1, 'decay_seconds' => 300]);

        $this->registerPasskey($this->seedIdentity());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertTrue($this->signInWithPasskey()->isSignedIn());
    }

    /**
     * A guard whose audience does not allow `passkey` refuses the sign-in as
     * `method_not_allowed` before anything is counted or used up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatDoesNotAllowPasskeysRefusesFirst(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $options = $this->signInOptions();

        config()->set('auth.guards.api.audience.methods', ['password']);

        $result = $this->sessions()->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $this->authenticator()->get($options->options)]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $result->reason);
        self::assertSame(1, PasskeyChallenge::query()->count());
    }

    /**
     * The passkey is used even when the session service then refuses its owner:
     * `PasskeyUsed` is dispatched and the count recorded, and the sign-in fails
     * as `identity_inactive`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePasskeyIsUsedEvenWhenItsOwnerIsThenRefused(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $identity->forceFill(['is_active' => false])->save();

        $this->recordEvents([AuthenticationFailed::class, PasskeyUsed::class]);

        $result = $this->signInWithPasskey();

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $result->reason);
        self::assertSame([PasskeyUsed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(1, Passkey::query()->sole()->sign_count);
    }

    /**
     * A failed passkey sign-in reports no credentials to Laravel's `Failed` and
     * no identifier to `AuthenticationFailed`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureReportsNoCredentials(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $this->signInWithPasskey(tamper: static fn (array $credential): array => self::withResponse($credential, 'signature', VirtualAuthenticator::encode('forged')));

        self::assertSame([], $this->recordedEvent(Failed::class)->credentials);
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->identifier);
        self::assertSame(AuthenticationFlow::SIGN_IN, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertSame('passkey', $this->recordedEvent(AuthenticationFailed::class)->context->method);
    }

    /**
     * Configure the guards and their relying party.
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
        self::configurePasskeys($config);
    }

    /**
     * Assert the sign-in failed with the reason in its result and the reason in
     * its one `AuthenticationFailed` event, and dispatched no `PasskeyUsed`.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $answered
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reported
     * @return void
     */
    private function assertFailed(SignInResult $result, FailureReason $answered, FailureReason $reported): void
    {
        self::assertTrue($result->isFailed());
        self::assertSame($answered, $result->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($reported, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * The credential with a member of its response set, or removed for `null`.
     *
     * @param  array<string, mixed>  $credential
     * @param  string  $member
     * @param  ?string  $value
     * @return array<string, mixed>
     */
    private static function withResponse(array $credential, string $member, ?string $value): array
    {
        $response = (array) $credential['response'];

        if ($value === null) {
            unset($response[$member]);
        } else {
            $response[$member] = $value;
        }

        return ['response' => $response] + $credential;
    }

    /**
     * Freeze the clocks at the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private static function freezeAt(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }
}
