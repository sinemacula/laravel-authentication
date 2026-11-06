<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyOwner;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Passkeys\RecordingPasskeyFactorGate;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests for the passkey service `Auth::passkeys()` returns: the options
 * a registration is handed, which challenges it may answer, what it stores and
 * reports, and what it refuses; sign-in options; the factor ceremony; and
 * listing and removing passkeys. Signing in with a passkey is tested in
 * `PasskeySignInTest`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyService::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(PasskeyChallenges::class)]
#[CoversClass(PasskeyCredentials::class)]
#[CoversClass(PasskeyOwner::class)]
#[CoversClass(PasskeySummary::class)]
#[CoversClass(AuthManager::class)]
final class PasskeyServiceTest extends TestCase
{
    use InteractsWithMachineClients, InteractsWithPasskeys, InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock and create the tables.
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

        $this->createSessionTables();

        self::createMachineClientsTable();
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Registration options ask for a discoverable, user-verified, unattested
     * credential of the guard's relying party for the identity, with a random
     * 32-byte challenge and handle, the display name defaulting to the user
     * name, and a timeout of the challenge's lifetime; the challenge is stored
     * for the guard, the relying party and the identity, with the options, for
     * five minutes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRegistrationOptionsAreStoredForTheIdentity(): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        self::assertTrue($options->expiresAt->equalTo($this->now->addMinutes(5)));
        self::assertSame(['id' => self::RP_ID, 'name' => 'Example'], $options->options['rp']);
        self::assertSame(['name' => self::USER_NAME, 'displayName' => self::USER_NAME], array_diff_key((array) $options->options['user'], ['id' => true]));
        self::assertSame(32, strlen(VirtualAuthenticator::decode(VirtualAuthenticator::at($options->options, 'user', 'id'))));
        self::assertSame(32, strlen(VirtualAuthenticator::decode(VirtualAuthenticator::at($options->options, 'challenge'))));
        self::assertSame(300000, $options->options['timeout']);
        self::assertSame(['requireResidentKey' => true, 'userVerification' => 'required', 'residentKey' => 'required'], $options->options['authenticatorSelection']);
        self::assertSame('none', $options->options['attestation']);
        self::assertSame([], $options->options['excludeCredentials']);

        $challenge = PasskeyChallenge::query()->sole();

        self::assertSame(
            [$options->challengeId, 'register', 'api', self::RP_ID, IntegrationIdentity::class, (string) $identity->id, $options->options],
            [$challenge->id, $challenge->purpose, $challenge->guard, $challenge->rp_id, $challenge->authenticatable_type, $challenge->authenticatable_id, $challenge->options],
        );
        self::assertTrue($challenge->expires_at->equalTo($this->now->addMinutes(5)));
    }

    /**
     * A display name given is shown instead of the user name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADisplayNameIsShownWhenGiven(): void
    {
        $options = Auth::passkeys('api')->registrationOptions($this->seedIdentity(), self::USER_NAME, 'Ada Lovelace');

        self::assertSame('Ada Lovelace', ((array) $options->options['user'])['displayName']);
    }

    /**
     * Rows of `[user name, display name]`: names a browser cannot show.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideBlankNames(): iterable
    {
        yield from [
            'an empty user name'    => ['', null],
            'a blank user name'     => [' ', 'Ada'],
            'an empty display name' => ['ada', ''],
            'a blank display name'  => ['ada', "\t"],
        ];
    }

    /**
     * A blank user name or display name is a misconfiguration, and stores no
     * challenge.
     *
     * @param  string  $userName
     * @param  ?string  $displayName
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBlankNames')]
    public function testABlankNameIsRefused(string $userName, ?string $displayName): void
    {
        $identity = $this->seedIdentity();

        try {
            Auth::passkeys('api')->registrationOptions($identity, $userName, $displayName);

            self::fail('Expected a blank name to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A passkey registration needs a non-empty user name, and a display name that is null or non-empty.', $exception->getMessage());
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * A registered passkey is stored for the identity and the relying party,
     * with its credential id (found by its digest), public key, user handle,
     * count, transports, backup state and name, and answered as `registered`
     * with a summary that holds none of the key material; `PasskeyAdded`
     * reports it with the passkey's id and the request's client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationStoresThePasskeyAndReportsIt(): void
    {
        $identity = $this->seedIdentity();

        $this->freshGuard();
        $this->recordEvents([PasskeyAdded::class]);

        $options = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $result  = Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), self::requestClient(), 'Work laptop');
        $summary = $result->passkey;

        self::assertTrue($result->isRegistered());
        self::assertSame(PasskeyRegistrationStatus::REGISTERED, $result->status);
        self::assertInstanceOf(PasskeySummary::class, $summary);
        self::assertSame(['Work laptop', ['internal', 'hybrid'], null], [$summary->name, $summary->transports, $summary->aaguid]);
        self::assertSame([true, true, null], [$summary->backupEligible, $summary->backedUp, $summary->lastUsedAt]);
        self::assertTrue($summary->createdAt->equalTo($this->now));

        $passkey = Passkey::query()->sole();
        $rawId   = VirtualAuthenticator::decode($this->authenticator()->lastCredentialId());

        self::assertSame($summary->id, $passkey->id);
        self::assertSame(hash('sha256', $rawId), $passkey->credential_id_hash);
        self::assertSame($this->authenticator()->lastCredentialId(), $passkey->credential_id);
        self::assertSame([IntegrationIdentity::class, (string) $identity->id, self::RP_ID], [$passkey->authenticatable_type, $passkey->authenticatable_id, $passkey->rp_id]);
        self::assertSame(((array) $options->options['user'])['id'], $passkey->user_handle);
        self::assertSame(0, $passkey->sign_count);
        self::assertTrue($passkey->uv_initialized);
        self::assertSame(0, PasskeyChallenge::query()->count());

        $event = $this->recordedEvent(PasskeyAdded::class);

        self::assertSame(['api', 'passkey', null], [$event->context->guard, $event->context->method, $event->context->scopes]);
        self::assertSame([$passkey->id, (string) $identity->id], [$event->context->credentialId, $event->context->identityId]);
        EventContextAssertions::assertIdentity($identity, $event->context);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$event->context->client->ip, $event->context->client->userAgent]);
    }

    /**
     * The client given is the one the event reports.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientGivenIsReported(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([PasskeyAdded::class]);

        $options = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), new ClientContext('198.51.100.4', 'Agent/2'));

        $client = $this->recordedEvent(PasskeyAdded::class)->context->client;

        self::assertSame(['198.51.100.4', 'Agent/2'], [$client->ip, $client->userAgent]);
    }

    /**
     * A registration's JSON form is accepted as well as its decoded form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationIsAcceptedAsJson(): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        $answer = (string) json_encode($this->authenticator()->create($options->options));

        self::assertTrue(Auth::passkeys('api')->register($identity, $options->challengeId, $answer, self::requestClient())->isRegistered());
    }

    /**
     * Rows of `[name given, name stored]`: a name is stored cleaned of invalid
     * UTF-8 and of control and bidirectional formatting characters, cut to 255
     * characters, and `null` when nothing is left.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideNames(): iterable
    {
        yield from [
            'none'            => [null, null],
            'empty'           => ['', null],
            'a NUL byte'      => ["Lap\0top", 'Laptop'],
            'a bidi override' => ["Lap\u{202E}top", 'Laptop'],
            'invalid UTF-8'   => ["Lap\xfftop", 'Lap?top'],
            'over 255 chars'  => [str_repeat('é', 300), str_repeat('é', 255)],
        ];
    }

    /**
     * A name is stored as the column can hold it.
     *
     * @param  ?string  $name
     * @param  ?string  $stored
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNames')]
    public function testANameIsStoredCleaned(?string $name, ?string $stored): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $summary  = Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), self::requestClient(), $name)->passkey;

        self::assertInstanceOf(PasskeySummary::class, $summary);
        self::assertSame($stored, $summary->name);
        self::assertSame($stored, Passkey::query()->sole()->name);
    }

    /**
     * Only the transports WebAuthn defines are kept, once each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyKnownTransportsAreKept(): void
    {
        $this->authenticator()->transports = ['usb', 'telepathy', 'nfc', 'usb', 'smart-card'];

        $summary = $this->registerPasskey($this->seedIdentity());

        self::assertSame(['usb', 'nfc', 'smart-card'], $summary->transports);
    }

    /**
     * An identity's later registrations exclude its passkeys and reuse the user
     * handle its first was registered under, including after the application
     * key changes; another identity gets a handle of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLaterRegistrationsReuseTheHandleAndExcludeEarlierPasskeys(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $first = Passkey::query()->sole();

        config()->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

        $options = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        self::assertSame($first->user_handle, ((array) $options->options['user'])['id']);
        self::assertSame([['type' => 'public-key', 'id' => $first->credential_id, 'transports' => ['internal', 'hybrid']]], $options->options['excludeCredentials']);

        Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), self::requestClient());

        self::assertSame([$first->user_handle], Passkey::query()->distinct()->pluck('user_handle')->all());

        $other = Auth::passkeys('api')->registrationOptions($this->seedIdentity('grace@example.test'), self::USER_NAME);

        self::assertNotSame($first->user_handle, ((array) $other->options['user'])['id']);
        self::assertSame([], $other->options['excludeCredentials']);
    }

    /**
     * Registrations whose options were handed out before the identity's first
     * passkey was registered each keep the handle their options gave, and each
     * passkey then signs in and verifies as a factor under its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRegistrationsStartedBeforeTheFirstCompletesKeepTheirOwnHandles(): void
    {
        $identity = $this->seedIdentity();
        $tablet   = new VirtualAuthenticator(self::ORIGIN);
        $laptop   = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $other    = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        Auth::passkeys('api')->register($identity, $laptop->challengeId, $this->authenticator()->create($laptop->options), self::requestClient());
        Auth::passkeys('api')->register($identity, $other->challengeId, $tablet->create($other->options), self::requestClient());

        $handles = [((array) $laptop->options['user'])['id'], ((array) $other->options['user'])['id']];

        self::assertNotSame($handles[0], $handles[1]);
        self::assertEqualsCanonicalizing($handles, Passkey::query()->pluck('user_handle')->all());

        foreach ([$this->authenticator(), $tablet] as $authenticator) {
            $signIn = Auth::passkeys('api')->signInOptions(self::requestClient());
            $result = $this->sessions('api')->signIn(
                'passkey',
                ['challenge' => $signIn->challengeId, 'credential' => $authenticator->get($signIn->options)],
                self::requestContext(),
            );
            $factor = self::factorCeremony(Auth::passkeys('api'), $identity);

            self::assertTrue($result->isSignedIn());
            self::assertTrue(self::verifyPasskeyFactor($identity, $factor->challengeId, $authenticator->get($factor->options))->isVerified());
        }
    }

    /**
     * Rows of `[challenge]`: challenges a registration of `ada` through `api`
     * cannot answer, each made by the closure.
     *
     * @return iterable<string, array{0: \Closure(self, \SineMacula\Laravel\Authentication\Contracts\Identity): string}>
     */
    public static function provideInvalidChallenges(): iterable
    {
        yield from [
            'an unknown id'       => [static fn (): string => '0192f6b2-0000-7000-8000-000000000001'],
            'not a UUID'          => [static fn (): string => 'challenge'],
            'another identity\'s' => [static fn (self $test): string => Auth::passkeys('api')->registrationOptions($test->seedIdentity('grace@x.test'), 'grace')->challengeId],
            'another guard\'s'    => [static fn (self $test, Identity $identity): string => Auth::passkeys('admin')->registrationOptions($identity, 'ada')->challengeId],
            'a sign-in challenge' => [static fn (): string => Auth::passkeys('api')->signInOptions(self::requestClient())->challengeId],
            'a factor challenge'  => [static function (self $test, Identity $identity): string {
                $test->registerPasskey($identity, 'api', new VirtualAuthenticator);

                return self::factorCeremony(Auth::passkeys('api'), $identity)->challengeId;
            }],
        ];
    }

    /**
     * A challenge that is not a live registration challenge of this guard for
     * the identity is refused as `challenge_invalid`, stores nothing, and is
     * left for its own ceremony.
     *
     * @param  \Closure(self, \SineMacula\Laravel\Authentication\Contracts\Identity): string  $challenge
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideInvalidChallenges')]
    public function testAChallengeOfAnotherCeremonyIsRefused(\Closure $challenge): void
    {
        $identity = $this->seedIdentity();
        $id       = $challenge($this, $identity);
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $before   = PasskeyChallenge::query()->count();
        $stored   = Passkey::query()->count();

        $this->recordEvents([PasskeyAdded::class]);

        $answer = $this->authenticator()->create($options->options);

        self::assertSame(PasskeyRegistrationStatus::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $id, $answer, self::requestClient())->status);
        self::assertSame($stored, Passkey::query()->count());
        self::assertSame($before, PasskeyChallenge::query()->count());
        self::assertSame([], $this->recorded);
    }

    /**
     * A registration challenge answers one registration: a second answer to it
     * is refused, even a valid one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeAnswersOneRegistration(): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        self::assertTrue(
            Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), self::requestClient())->isRegistered(),
        );
        $answer = $this->authenticator()->create($options->options);

        self::assertSame(PasskeyRegistrationStatus::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $options->challengeId, $answer, self::requestClient())->status);
        self::assertSame(1, Passkey::query()->count());
    }

    /**
     * A challenge answered at or after its expiry is refused, and one answered
     * the second before is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredChallengeIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $expired  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $live     = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        self::freezeAt($this->now->addSeconds(299));

        self::assertTrue(Auth::passkeys('api')->register($identity, $live->challengeId, $this->authenticator()->create($live->options), self::requestClient())->isRegistered());

        self::freezeAt($this->now->addSeconds(300));

        $answer = $this->authenticator()->create($expired->options);

        self::assertSame(PasskeyRegistrationStatus::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $expired->challengeId, $answer, self::requestClient())->status);
    }

    /**
     * A challenge issued for a relying party the guard no longer has is
     * refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeOfAnotherRelyingPartyIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        config()->set('auth.guards.api.passkeys', ['id' => 'app.example.test']);

        $answer = $this->authenticator()->create($options->options);

        self::assertSame(PasskeyRegistrationStatus::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $options->challengeId, $answer, self::requestClient())->status);
    }

    /**
     * A response that is malformed, that fails its ceremony, or that is an
     * assertion is refused as `response_invalid`, and uses the challenge up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResponseThatDoesNotVerifyIsRefusedAndUsesTheChallengeUp(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $malformed = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $foreign   = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $assertion = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        $wrongOrigin         = new VirtualAuthenticator('https://evil.test');
        $assertionCredential = $this->authenticator()->get($this->signInOptions()->options);

        self::assertSame(PasskeyRegistrationStatus::RESPONSE_INVALID, Auth::passkeys('api')->register($identity, $malformed->challengeId, '{', self::requestClient())->status);
        $foreignAnswer = $wrongOrigin->create($foreign->options);

        self::assertSame(
            PasskeyRegistrationStatus::RESPONSE_INVALID,
            Auth::passkeys('api')->register($identity, $foreign->challengeId, $foreignAnswer, self::requestClient())->status,
        );
        self::assertSame(
            PasskeyRegistrationStatus::RESPONSE_INVALID,
            Auth::passkeys('api')->register($identity, $assertion->challengeId, $assertionCredential, self::requestClient())->status,
        );
        self::assertSame(1, Passkey::query()->count());
        self::assertSame(0, PasskeyChallenge::query()->where('purpose', 'register')->count());
    }

    /**
     * A credential registered already, for this identity or another, is refused
     * as `already_registered` and reported by no event.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialRegisteredAlreadyIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        $this->registerPasskey($identity);

        $rawId = VirtualAuthenticator::decode($this->authenticator()->lastCredentialId());

        $this->recordEvents([PasskeyAdded::class]);

        foreach ([$identity, $other] as $registrant) {
            $options = Auth::passkeys('api')->registrationOptions($registrant, self::USER_NAME);

            $answer = $this->authenticator()->create($options->options, id: $rawId);

            self::assertSame(
                PasskeyRegistrationStatus::ALREADY_REGISTERED,
                Auth::passkeys('api')->register($registrant, $options->challengeId, $answer, self::requestClient())->status,
            );
        }

        self::assertSame(1, Passkey::query()->count());
        self::assertSame([], $this->recorded);
    }

    /**
     * A passkey registered inside a transaction on its connection is reported
     * once the transaction commits, and not at all when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEventWaitsForTheRegistrationToCommit(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([PasskeyAdded::class]);

        DB::beginTransaction();

        $this->registerPasskey($identity);

        self::assertSame([], $this->recorded);

        DB::rollBack();

        self::assertSame([], $this->recorded);
        self::assertSame(0, Passkey::query()->count());

        DB::transaction(function () use ($identity): void {
            $this->registerPasskey($identity);

            self::assertSame([], $this->recorded);
        });

        self::assertSame([PasskeyAdded::class], $this->recordedClasses());
    }

    /**
     * An authenticator that names itself is recorded by its AAGUID.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAuthenticatorsAaguidIsRecorded(): void
    {
        $this->authenticator()->aaguid = (string) hex2bin('adce000235bcc60a648b0b25f1f05503');

        $summary = $this->registerPasskey($this->seedIdentity());

        self::assertSame('adce0002-35bc-c60a-648b-0b25f1f05503', $summary->aaguid);
        self::assertSame('adce0002-35bc-c60a-648b-0b25f1f05503', Passkey::query()->sole()->aaguid);
    }

    /**
     * An identity that is not saved yet cannot hold a passkey, and nothing is
     * written for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNotSavedIsRefused(): void
    {
        try {
            Auth::passkeys('api')->registrationOptions(new IntegrationIdentity(['email' => 'new@example.test']), self::USER_NAME);

            self::fail('Expected an unsaved identity to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(IntegrationIdentity::class . ' must be saved before it can hold passkeys.', $exception->getMessage());
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * A machine identity signs in with no passkey: every ceremony that names an
     * identity refuses it as a misconfiguration, writing nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineIdentityIsRefused(): void
    {
        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);
        $calls   = [
            static fn (): mixed => Auth::passkeys('api')->registrationOptions($machine, 'robot'),
            static fn (): mixed => Auth::passkeys('api')->register($machine, '0192f6b2-0000-7000-8000-000000000001', '{}', self::requestClient()),
            static fn (): mixed => self::factorCeremony(Auth::passkeys('api'), $machine),
            static fn (): mixed => Auth::passkeys('api')->verifyFactor(
                $machine,
                self::factorBinding($machine),
                '0192f6b2-0000-7000-8000-000000000001',
                '{}',
                self::requestClient(),
            ),
            static fn (): mixed => Auth::passkeys('api')->passkeys($machine),
            static fn (): mixed => Auth::passkeys('api')->remove($machine, '0192f6b2-0000-7000-8000-000000000001', self::requestClient()),
        ];

        foreach ($calls as $call) {
            try {
                $call();

                self::fail('Expected a machine identity to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(MachineClient::class . ' is a machine identity, which signs in with no passkey.', $exception->getMessage());
            }
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * An identity that is not an Eloquent model cannot own a passkey.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNotAModelIsRefused(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Passkeys can only belong to an Eloquent identity; ' . $identity::class . ' is not a model.');

        Auth::passkeys('api')->registrationOptions($identity, 'ada');
    }

    /**
     * A guard without a relying party fails closed, naming the guard and the
     * key, before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardWithoutARelyingPartyFailsClosed(): void
    {
        config()->set('authentication.passkeys.relying_party.id', null);

        try {
            Auth::passkeys('api')->registrationOptions($this->seedIdentity(), 'ada');

            self::fail('Expected the relying party to fail closed.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Passkey relying party `id` for guard [api] must be', $exception->getMessage());
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * The passkey service belongs to a jwt guard: the default one, or the one
     * named; any other guard has none.
     *
     * @return void
     */
    public function testTheServiceBelongsToAJwtGuard(): void
    {
        config()->set('auth.defaults.guard', 'api');

        self::assertInstanceOf(PasskeyService::class, Auth::passkeys());
        self::assertInstanceOf(PasskeyService::class, Auth::passkeys('admin'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is not a jwt guard, so it has no passkey service.');

        Auth::passkeys('web');
    }

    /**
     * Sign-in options name no credential, require user verification, carry a
     * random 32-byte challenge for the relying party, and store a sign-in
     * challenge bound to no identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInOptionsAreUsernameless(): void
    {
        $this->freshGuard();

        $options = Auth::passkeys('api')->signInOptions(self::requestClient());

        self::assertSame([[], 'required'], [$options->options['allowCredentials'], $options->options['userVerification']]);
        self::assertSame([self::RP_ID, 300000], [$options->options['rpId'], $options->options['timeout']]);
        self::assertSame(32, strlen(VirtualAuthenticator::decode(VirtualAuthenticator::at($options->options, 'challenge'))));
        self::assertNotSame($options->options['challenge'], Auth::passkeys('api')->signInOptions(self::requestClient())->options['challenge']);

        $challenge = PasskeyChallenge::query()->findOrFail($options->challengeId);

        self::assertSame(['sign_in', 'api', self::RP_ID], [$challenge->purpose, $challenge->guard, $challenge->rp_id]);
        self::assertSame([null, null], [$challenge->authenticatable_type, $challenge->authenticatable_id]);
        self::assertTrue($options->expiresAt->equalTo($this->now->addSeconds(300)));
    }

    /**
     * Each request is counted against the client's IP address under the guard's
     * `passkey_options` limit; once it is used up, a 429 says how long to wait
     * and nothing is stored. Another IP address is not held back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOptionsAreLimitedPerIpAddress(): void
    {
        config()->set('authentication.rate_limits.passkey_options.per_ip', ['max' => 2, 'decay_seconds' => 300]);

        $this->freshGuard();

        Auth::passkeys('api')->signInOptions(self::requestClient());
        Auth::passkeys('api')->signInOptions(self::requestClient());

        self::assertSame(2, self::counterHits('api', 'passkey_options', 'per_ip', self::CLIENT_IP));

        try {
            Auth::passkeys('api')->signInOptions(self::requestClient());

            self::fail('Expected the third request to be throttled.');
        } catch (ThrottleRequestsException $exception) {
            self::assertSame(429, $exception->getStatusCode());
            self::assertSame(['Retry-After' => 300], $exception->getHeaders());
        }

        self::assertSame(2, PasskeyChallenge::query()->count());
        $elsewhere = Auth::passkeys('api')->signInOptions(new ClientContext('198.51.100.1', null));

        self::assertInstanceOf(PasskeyChallenge::class, PasskeyChallenge::query()->find($elsewhere->challengeId));
    }

    /**
     * The limit is the guard's own when it sets one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardsOwnLimitApplies(): void
    {
        config()->set('auth.guards.api.rate_limits', ['passkey_options' => ['per_ip' => ['max' => 1, 'decay_seconds' => 60]]]);

        $this->freshGuard();

        Auth::passkeys('api')->signInOptions(self::requestClient());

        $this->expectException(ThrottleRequestsException::class);

        Auth::passkeys('api')->signInOptions(self::requestClient());
    }

    /**
     * Factor options allow only the identity's passkeys for the relying party,
     * with their transports, require user verification, and store a factor
     * challenge bound to the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFactorOptionsAllowOnlyTheIdentitysPasskeys(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        $this->registerPasskey($identity);
        $this->registerPasskey($other, authenticator: new VirtualAuthenticator(self::ORIGIN));

        $options = self::factorCeremony(Auth::passkeys('api'), $identity);
        $own     = Passkey::query()->where('authenticatable_id', (string) $identity->id)->sole();

        self::assertSame([['type' => 'public-key', 'id' => $own->credential_id, 'transports' => ['internal', 'hybrid']]], $options->options['allowCredentials']);
        self::assertSame(['required', self::RP_ID], [$options->options['userVerification'], $options->options['rpId']]);

        $challenge = PasskeyChallenge::query()->findOrFail($options->challengeId);

        self::assertSame(['factor', (string) $identity->id], [$challenge->purpose, $challenge->authenticatable_id]);
    }

    /**
     * The identity's passkey verifies as a factor: verified, with the summary
     * of the passkey as its use left it, its count and use recorded,
     * `PasskeyUsed` reported with the client given, and no failure reported or
     * attempt counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitysPasskeyVerifiesAsAFactor(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        self::freezeAt($this->now->addSeconds(60));

        $options = self::factorCeremony(Auth::passkeys('api'), $identity);

        $this->recordEvents([PasskeyUsed::class, AuthenticationFailed::class]);

        $answer  = $this->authenticator()->get($options->options);
        $outcome = Auth::passkeys('api')->verifyFactor($identity, self::factorBinding($identity), $options->challengeId, $answer, new ClientContext('198.51.100.9', 'Factor/1'));

        self::assertTrue($outcome->isVerified());
        self::assertNull($outcome->reason);

        $summary = $outcome->assertion?->passkey;

        self::assertInstanceOf(PasskeySummary::class, $summary);
        self::assertSame([$passkey->id, 'Laptop'], [$summary->id, $summary->name]);
        self::assertTrue($summary->createdAt->equalTo($this->now));
        self::assertTrue($summary->lastUsedAt?->equalTo($this->now->addSeconds(60)));
        self::assertSame([PasskeyUsed::class], $this->recordedClasses());

        $used = $this->recordedEvent(PasskeyUsed::class);

        self::assertSame(['api', 'passkey'], [$used->context->guard, $used->context->method]);
        self::assertSame([$passkey->id, '198.51.100.9'], [$used->context->credentialId, $used->context->client->ip]);
        self::assertSame(1, Passkey::query()->sole()->sign_count);
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A response that carries no user handle verifies too: the identity is
     * known, so the passkey's own handle is the one checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResponseWithoutAUserHandleVerifies(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $options  = self::factorCeremony(Auth::passkeys('api'), $identity);
        $response = $this->authenticator()->get($options->options);

        unset($response['response']['userHandle']);

        self::assertTrue(
            Auth::passkeys('api')->verifyFactor(
                $identity,
                self::factorBinding($identity),
                $options->challengeId,
                (string) json_encode($response),
                self::requestClient(),
            )->isVerified(),
        );
    }

    /**
     * Another identity's passkey is no factor of this one, even answering this
     * identity's challenge: `invalid_credentials`, and it is not touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherIdentitysPasskeyIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $theirs   = $this->registerPasskey($other);

        $this->registerPasskey($identity, 'api', new VirtualAuthenticator);

        $options = self::factorCeremony(Auth::passkeys('api'), $identity);

        $this->recordEvents([PasskeyUsed::class, AuthenticationFailed::class]);

        $answer = $this->authenticator()->get(['allowCredentials' => []] + $options->options);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, self::verifyPasskeyFactor($identity, $options->challengeId, $answer)->reason);
        self::assertSame(0, Passkey::query()->findOrFail($theirs->id)->sign_count);
        self::assertSame([], $this->recorded);
    }

    /**
     * A challenge that is not a live factor challenge for the identity is
     * refused as `passkey_challenge_invalid`: another identity's, a sign-in's,
     * an unknown one, and one answered already.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeThatIsNotTheIdentitysFactorChallengeIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        $this->registerPasskey($identity);
        $this->registerPasskey($other, 'api', new VirtualAuthenticator);

        $own      = self::factorCeremony(Auth::passkeys('api'), $identity);
        $response = $this->authenticator()->get($own->options);

        foreach ([self::factorCeremony(Auth::passkeys('api'), $other)->challengeId, $this->signInOptions()->challengeId, '0192f6b2-0000-7000-8000-000000000001'] as $challenge) {
            self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, self::verifyPasskeyFactor($identity, $challenge, $response)->reason);
        }

        self::assertTrue(Auth::passkeys('api')->verifyFactor($identity, self::factorBinding($identity), $own->challengeId, $response, self::requestClient())->isVerified());
        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, self::verifyPasskeyFactor($identity, $own->challengeId, $response)->reason);
    }

    /**
     * A malformed or unverified response is refused as `invalid_credentials`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResponseThatDoesNotVerifyIsRefused(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $malformed = self::factorCeremony(Auth::passkeys('api'), $identity);

        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            Auth::passkeys('api')->verifyFactor($identity, self::factorBinding($identity), $malformed->challengeId, '{}', self::requestClient())->reason,
        );

        $this->authenticator()->userVerified = false;

        $unverified = self::factorCeremony(Auth::passkeys('api'), $identity);

        $answer = $this->authenticator()->get($unverified->options);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, self::verifyPasskeyFactor($identity, $unverified->challengeId, $answer)->reason);
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * A count that does not advance is refused as `passkey_counter_regressed`,
     * not concealed: the caller already holds the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACountThatDoesNotAdvanceIsRefused(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $first = self::factorCeremony(Auth::passkeys('api'), $identity);

        self::assertTrue(self::verifyPasskeyFactor($identity, $first->challengeId, $this->authenticator()->get($first->options))->isVerified());

        $this->authenticator()->setCounter($this->authenticator()->lastCredentialId(), 0);

        $again = self::factorCeremony(Auth::passkeys('api'), $identity);

        $answer = $this->authenticator()->get($again->options);

        self::assertSame(FailureReason::PASSKEY_COUNTER_REGRESSED, self::verifyPasskeyFactor($identity, $again->challengeId, $answer)->reason);
        self::assertSame(1, Passkey::query()->sole()->sign_count);
    }

    /**
     * A use inside a transaction on the passkey's connection is reported once
     * it commits, and not at all when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUseIsReportedOnceCommitted(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);
        $this->recordEvents([PasskeyUsed::class]);

        DB::beginTransaction();

        $options = self::factorCeremony(Auth::passkeys('api'), $identity);

        self::assertTrue(self::verifyPasskeyFactor($identity, $options->challengeId, $this->authenticator()->get($options->options))->isVerified());
        self::assertSame([], $this->recorded);

        DB::rollBack();

        self::assertSame([], $this->recorded);
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * An identity's passkeys are listed oldest first, for the guard's relying
     * party only, never another identity's (nor one of an identity of another
     * type that shares its id), and as summaries that hold no key material.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentitysPasskeysAreListedForTheRelyingParty(): void
    {
        $identity = $this->seedIdentity();

        $first = $this->registerPasskey($identity);

        self::freezeAt($this->now->addMinute());

        $second = $this->registerPasskey($identity, authenticator: new VirtualAuthenticator(self::ORIGIN));

        $this->registerPasskey($this->seedIdentity('grace@example.test'), authenticator: new VirtualAuthenticator(self::ORIGIN));

        config()->set('auth.guards.admin.passkeys', ['id' => 'app.example.test']);

        $this->registerPasskey($identity, 'admin', new VirtualAuthenticator(self::ORIGIN));

        $listed = Auth::passkeys('api')->passkeys($identity);

        self::assertSame([$first->id, $second->id], array_map(static fn (PasskeySummary $summary): string => $summary->id, $listed));
        self::assertSame(['id', 'name', 'transports', 'aaguid', 'backup_eligible', 'backed_up', 'created_at', 'last_used_at'], array_keys($listed[0]->toArray()));
        self::assertCount(1, Auth::passkeys('admin')->passkeys($identity));
        self::assertSame([], Auth::passkeys('api')->passkeys($this->seedIdentity('alan@example.test')));

        self::passkeyOfAnotherType($first->id);

        self::assertCount(2, Auth::passkeys('api')->passkeys($identity));
    }

    /**
     * A listed passkey shows when it was last used.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListedPasskeyShowsItsLastUse(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        self::freezeAt($this->now->addHour());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame('2026-04-06T13:00:00+00:00', Auth::passkeys('api')->passkeys($identity)[0]->toArray()['last_used_at']);
    }

    /**
     * Removing an identity's passkey deletes it and reports `PasskeyRemoved`
     * with the passkey's id and the client given, with no completion while no
     * factor package is bound; removing it again removes nothing and reports
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAPasskeyDeletesItAndReportsItOnce(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        $this->recordEvents([PasskeyRemoved::class]);

        $removal = Auth::passkeys('api')->remove($identity, $passkey->id, new ClientContext('198.51.100.3', 'Remover/1'));

        self::assertTrue($removal->isRemoved());
        self::assertNull($removal->completion);
        self::assertSame(0, Passkey::query()->count());

        $event = $this->recordedEvent(PasskeyRemoved::class);

        self::assertSame(['api', 'passkey', $passkey->id, (string) $identity->id, '198.51.100.3'], [
            $event->context->guard,
            $event->context->method,
            $event->context->credentialId,
            $event->context->identityId,
            $event->context->client->ip,
        ]);

        self::assertFalse(Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient())->isRemoved());
        self::assertCount(1, $this->recorded);
    }

    /**
     * Another identity's passkey, one of an identity of another type that
     * shares this one's id, one of another relying party, and an id that names
     * none are not removed, and nothing is reported, while the identity's own
     * passkey stays; an id that is not a UUID is refused without a query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheIdentitysPasskeyOfTheRelyingPartyIsRemoved(): void
    {
        $identity  = $this->seedIdentity();
        $other     = $this->seedIdentity('grace@example.test');
        $foreign   = $this->registerPasskey($other);
        $own       = $this->registerPasskey($identity, authenticator: new VirtualAuthenticator(self::ORIGIN));
        $namesakes = self::passkeyOfAnotherType($own->id);

        config()->set('auth.guards.admin.passkeys', ['id' => 'app.example.test']);

        $elsewhere = $this->registerPasskey($identity, 'admin', new VirtualAuthenticator(self::ORIGIN));

        $this->recordEvents([PasskeyRemoved::class]);

        self::assertFalse(Auth::passkeys('api')->remove($identity, $foreign->id, self::requestClient())->isRemoved());
        self::assertFalse(Auth::passkeys('api')->remove($identity, $namesakes, self::requestClient())->isRemoved());
        self::assertFalse(Auth::passkeys('api')->remove($identity, $elsewhere->id, self::requestClient())->isRemoved());
        self::assertFalse(Auth::passkeys('api')->remove($identity, '0192f6b2-0000-7000-8000-000000000001', self::requestClient())->isRemoved());

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertFalse(Auth::passkeys('api')->remove($identity, 'not-a-uuid', self::requestClient())->isRemoved());
        self::assertSame(0, $queries);
        self::assertSame(4, Passkey::query()->count());
        self::assertSame([], $this->recorded);
    }

    /**
     * Of an identity's two passkeys, removing one keeps the other.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingOnePasskeyKeepsTheOthers(): void
    {
        $identity = $this->seedIdentity();
        $removed  = $this->registerPasskey($identity);
        $kept     = $this->registerPasskey($identity, authenticator: new VirtualAuthenticator(self::ORIGIN));

        self::assertTrue(Auth::passkeys('api')->remove($identity, $removed->id, self::requestClient())->isRemoved());
        self::assertSame([$kept->id], array_map(static fn (PasskeySummary $summary): string => $summary->id, Auth::passkeys('api')->passkeys($identity)));
    }

    /**
     * A removal inside a transaction on the passkey's connection is reported
     * once it commits, and not at all when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalIsReportedOnceCommitted(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        $this->recordEvents([PasskeyRemoved::class]);

        DB::beginTransaction();

        self::assertTrue(Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient())->isRemoved());
        self::assertSame([], $this->recorded);

        DB::rollBack();

        self::assertSame([], $this->recorded);
        self::assertSame(1, Passkey::query()->count());

        DB::transaction(static function () use ($identity, $passkey): void {
            Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient());
        });

        self::assertSame([PasskeyRemoved::class], $this->recordedClasses());
    }

    /**
     * Every event goes, once committed, to the dispatcher the guard has when
     * the commit runs it: the addition, the use and the removal all reach the
     * one swapped in after the last write, and neither the dispatcher of the
     * addition nor the one swapped in between the writes receives any.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryEventReachesTheDispatcherBoundAtTheCommit(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();
        $passkeys = Auth::passkeys('api');
        $swapped  = new Dispatcher(app());
        $last     = new Dispatcher(app());
        $received = [];
        $late     = [];

        $swapped->listen([PasskeyAdded::class, PasskeyUsed::class, PasskeyRemoved::class], static function (object $event) use (&$received): void {
            $received[] = $event::class;
        });

        $last->listen([PasskeyAdded::class, PasskeyUsed::class, PasskeyRemoved::class], static function (object $event) use (&$late): void {
            $late[] = $event::class;
        });

        $this->recordEvents([PasskeyAdded::class, PasskeyUsed::class, PasskeyRemoved::class]);

        DB::transaction(function () use ($identity, $guard, $passkeys, $swapped, $last): void {
            $registration = $passkeys->registrationOptions($identity, self::USER_NAME);
            $registered   = $passkeys->register($identity, $registration->challengeId, $this->authenticator()->create($registration->options), self::requestClient());

            $guard->setDispatcher($swapped);

            $factor = self::factorCeremony($passkeys, $identity);

            self::assertTrue(
                $passkeys->verifyFactor(
                    $identity,
                    self::factorBinding($identity),
                    $factor->challengeId,
                    $this->authenticator()->get($factor->options),
                    self::requestClient(),
                )->isVerified(),
            );
            self::assertNotNull($registered->passkey);
            self::assertTrue($passkeys->remove($identity, $registered->passkey->id, self::requestClient())->isRemoved());

            $guard->setDispatcher($last);
        });

        self::assertSame([], $this->recordedClasses());
        self::assertSame([], $received);
        self::assertSame([PasskeyAdded::class, PasskeyUsed::class, PasskeyRemoved::class], $late);
    }

    /**
     * A factor package that asks for a registration on a session gives its
     * binding: it must name this identity, this guard and a session, and its
     * session and purpose are kept on the challenge; without one the challenge
     * records none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationKeepsTheBindingItWasAskedFor(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $passkeys = Auth::passkeys('api');

        $passkeys->registrationOptions($identity, self::USER_NAME, binding: new ProofBinding($identity, 'api', 'pending-1', Purpose::ENROLLMENT));

        self::assertSame(['pending-1', 'enrollment'], [PasskeyChallenge::query()->sole()->session_id, PasskeyChallenge::query()->sole()->binding_purpose]);

        PasskeyChallenge::query()->delete();

        $passkeys->registrationOptions($identity, self::USER_NAME);

        self::assertSame([null, null], [PasskeyChallenge::query()->sole()->session_id, PasskeyChallenge::query()->sole()->binding_purpose]);

        $bindings = [
            new ProofBinding($other, 'api', 's', Purpose::ENROLLMENT),
            new ProofBinding(\Mockery::mock(Identity::class), 'api', 's', Purpose::ENROLLMENT),
            new ProofBinding($identity, 'admin', 's', Purpose::ENROLLMENT),
            new ProofBinding($identity, 'api', null, Purpose::ENROLLMENT),
            new ProofBinding($identity, 'api', str_repeat('s', 256), Purpose::ENROLLMENT),
        ];

        self::assertNotNull($passkeys->registrationOptions($identity, self::USER_NAME, binding: new ProofBinding($identity, 'api', str_repeat('s', 255), Purpose::ENROLLMENT)));

        PasskeyChallenge::query()->latest('id')->firstOrFail()->delete();

        foreach ($bindings as $binding) {
            try {
                $passkeys->registrationOptions($identity, self::USER_NAME, binding: $binding);

                self::fail('A binding that does not name this identity, guard and a session was taken.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('[api]', $exception->getMessage());
            }
        }

        self::assertSame(1, PasskeyChallenge::query()->count());
    }

    /**
     * Inside the registration's transaction on the storage connection, before
     * the row is written, the factor gate is asked about the passkey as the
     * registration showed it (the row's id, the canonical credential id, the
     * relying party, the flags its authenticator data reported, resistant to
     * phishing and with no key protection, and the time), with the challenge's
     * binding and the cleaned name; its association comes back with the
     * passkey, which is stored and reported once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorGateAssociatesARegisteredPasskey(): void
    {
        $identity = $this->seedIdentity();
        $gate     = new RecordingPasskeyFactorGate;

        app()->instance(PasskeyFactorGate::class, $gate);

        $this->authenticator()->backedUp = false;

        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->registrationOptions($identity, self::USER_NAME, binding: new ProofBinding($identity, 'api', 'pending-1', Purpose::ENROLLMENT));
        $answer   = $this->authenticator()->create($options->options);

        $this->recordEvents([PasskeyAdded::class]);

        $result = $passkeys->register($identity, $options->challengeId, $answer, self::requestClient(), "Work\0 laptop");
        $stored = Passkey::query()->sole();

        self::assertTrue($result->isRegistered());
        self::assertSame('factor-' . $stored->id, $result->factor?->factor);
        self::assertCount(1, $gate->registrations);

        ['identity' => $asked, 'application' => $application, 'passkey' => $seen, 'binding' => $binding, 'name' => $name] = $gate->registrations[0];

        self::assertSame([$identity, 'api', 'Work laptop'], [$asked, $application, $name]);
        self::assertSame([$stored->id, $stored->credential_id, self::RP_ID], [$seen->id, $seen->credentialId, $seen->rpId]);
        self::assertSame($this->authenticator()->lastCredentialId(), $stored->credential_id);
        self::assertEquals(new ObservedProperties(true, true, true, false, true), $seen->observed);
        self::assertTrue($seen->registeredAt->equalTo($this->now));
        self::assertNotNull($binding);
        self::assertSame([$identity, 'api', 'pending-1', Purpose::ENROLLMENT], [$binding->identity, $binding->application, $binding->sessionId, $binding->purpose]);
        self::assertSame([PasskeyAdded::class], $this->recordedClasses());
    }

    /**
     * A gate that refuses a registration throws: the exception reaches the
     * caller, no passkey is stored or reported, nothing the gate did stands,
     * and the challenge stays used up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGateThatRefusesARegistrationStoresNothing(): void
    {
        $identity = $this->seedIdentity();

        app()->instance(PasskeyFactorGate::class, new RecordingPasskeyFactorGate(static function (): never {
            DB::table('integration_identities')->update(['email' => 'changed@example.test']);

            throw new \RuntimeException('Refused by the factor package.');
        }));

        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->registrationOptions($identity, self::USER_NAME);
        $answer   = $this->authenticator()->create($options->options);

        $this->recordEvents([PasskeyAdded::class]);

        try {
            $passkeys->register($identity, $options->challengeId, $answer, self::requestClient());

            self::fail('The refusal did not reach the caller.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Refused by the factor package.', $exception->getMessage());
        }

        self::assertSame(0, Passkey::query()->count());
        self::assertSame(0, PasskeyChallenge::query()->count());
        self::assertSame('ada@example.test', DB::table('integration_identities')->value('email'));
        self::assertSame([], $this->recorded);
    }

    /**
     * A credential registered already is answered `already_registered` before
     * the gate is asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialRegisteredAlreadyNeverReachesTheGate(): void
    {
        $identity = $this->seedIdentity();
        $gate     = new RecordingPasskeyFactorGate;

        app()->instance(PasskeyFactorGate::class, $gate);

        $passkeys = Auth::passkeys('api');
        $first    = $passkeys->registrationOptions($identity, self::USER_NAME);
        $answer   = $this->authenticator()->create($first->options);

        self::assertTrue($passkeys->register($identity, $first->challengeId, $answer, self::requestClient())->isRegistered());

        $again = $passkeys->registrationOptions($identity, self::USER_NAME);
        $copy  = $this->authenticator()->create($again->options, id: VirtualAuthenticator::decode($this->authenticator()->lastCredentialId()));

        self::assertSame(PasskeyRegistrationStatus::ALREADY_REGISTERED, $passkeys->register($identity, $again->challengeId, $copy, self::requestClient())->status);
        self::assertCount(1, $gate->registrations);
    }

    /**
     * A credential another registration stores while the gate runs is found
     * only by the insert: the whole change rolls back, the gate's work with it
     * (here a pending session it satisfied, which stays pending and unbound),
     * and the registration is answered `already_registered`, reporting
     * nothing; a gate that completes the pending session commits with the
     * registration, which binds the guard once it commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGateThatSatisfiesAPendingSessionCommitsOrRollsBackWithTheRegistration(): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential->reveal();
        $proof      = self::adapterProof($identity, 'api', $pending->pending->id, Purpose::ENROLLMENT);
        $sessions   = $this->sessions();
        $duplicate  = new \ArrayObject(['insert' => true]);

        $registering = static function (RegisteredPasskey $passkey) use ($sessions, $credential, $proof, $duplicate): PasskeyFactorAssociation {
            self::assertTrue($sessions->satisfy($credential, $proof, self::requestClient())->isSignedIn());

            if ($duplicate['insert'] === true) {
                DB::table('passkeys')->insert([
                    'id'                   => (string) Str::uuid(),
                    'credential_id_hash'   => hash('sha256', VirtualAuthenticator::decode($passkey->credentialId)),
                    'credential_id'        => $passkey->credentialId,
                    'authenticatable_type' => MachineClient::class,
                    'authenticatable_id'   => '1',
                    'rp_id'                => self::RP_ID,
                    'user_handle'          => 'aGFuZGxl',
                    'public_key'           => 'a2V5',
                    'transports'           => '[]',
                ]);
            }

            return new PasskeyFactorAssociation('factor-1');
        };

        app()->instance(PasskeyFactorGate::class, new RecordingPasskeyFactorGate($registering));

        $passkeys = Auth::passkeys('api');
        $guard    = Auth::guard('api');
        $options  = $passkeys->registrationOptions($identity, self::USER_NAME);
        $answer   = $this->authenticator()->create($options->options);

        $this->recordEvents([PasskeyAdded::class, Login::class]);

        $refused = $passkeys->register($identity, $options->challengeId, $answer, self::requestClient());

        self::assertSame(PasskeyRegistrationStatus::ALREADY_REGISTERED, $refused->status);
        self::assertNull($refused->factor);
        self::assertSame(0, Passkey::query()->count());
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertFalse($guard->hasUser());
        self::assertSame([], $this->recorded);

        $duplicate['insert'] = false;

        $options = $passkeys->registrationOptions($identity, self::USER_NAME);

        self::assertSame(
            'factor-1',
            $passkeys->register($identity, $options->challengeId, $this->authenticator()->create($options->options), self::requestClient())->factor?->factor,
        );
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertTrue($guard->hasUser());
        self::assertSame([Login::class, PasskeyAdded::class], $this->recordedClasses());
    }

    /**
     * A gate that judges an active current session again once the passkey
     * counts as a factor (`factorChanged()` with `PASSKEY_FACTOR_REGISTERED`)
     * answers the judgement as its association's completion, which the
     * registration hands back as it is: a session now short of a further factor
     * returns to pending with the registration, the completion carrying the
     * pending session and its credential, and that credential takes a further
     * factor. A duplicate of the credential the gate itself inserts, an
     * injected conflict in the same transaction found only by the passkey's own
     * insert, rolls the return back with the rest, so the session stays active,
     * nothing is reported and no association is answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGateThatJudgesTheCurrentSessionAgainHandsItsCompletionBackWithTheRegistration(): void
    {
        $identity = $this->seedIdentity();
        $signedIn = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($signedIn);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $record    = $signedIn->record;
        $duplicate = new \ArrayObject(['insert' => true]);

        $registering = static function (RegisteredPasskey $passkey) use ($identity, $record, $duplicate): PasskeyFactorAssociation {
            $judgement = Auth::sessions('api')->factorChanged($identity, FactorChangeMade::PASSKEY_FACTOR_REGISTERED, $record);

            if ($duplicate['insert'] === true) {
                DB::table('passkeys')->insert([
                    'id'                   => (string) Str::uuid(),
                    'credential_id_hash'   => hash('sha256', VirtualAuthenticator::decode($passkey->credentialId)),
                    'credential_id'        => $passkey->credentialId,
                    'authenticatable_type' => MachineClient::class,
                    'authenticatable_id'   => '1',
                    'rp_id'                => self::RP_ID,
                    'user_handle'          => 'aGFuZGxl',
                    'public_key'           => 'a2V5',
                    'transports'           => '[]',
                ]);
            }

            return new PasskeyFactorAssociation('factor-1', $judgement);
        };

        app()->instance(PasskeyFactorGate::class, new RecordingPasskeyFactorGate($registering));

        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->registrationOptions($identity, self::USER_NAME);
        $answer   = $this->authenticator()->create($options->options);

        $this->recordEvents([PasskeyAdded::class, SessionReturnedToPending::class]);

        $refused = $passkeys->register($identity, $options->challengeId, $answer, self::requestClient());

        self::assertSame(PasskeyRegistrationStatus::ALREADY_REGISTERED, $refused->status);
        self::assertNull($refused->factor);
        self::assertSame(0, Passkey::query()->count());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertSame([], $this->recorded);

        $duplicate['insert'] = false;

        $options      = $passkeys->registrationOptions($identity, self::USER_NAME);
        $registration = $passkeys->register($identity, $options->challengeId, $this->authenticator()->create($options->options), self::requestClient());
        $judgement    = $registration->factor?->completion;

        self::assertTrue($registration->isRegistered());
        self::assertInstanceOf(FactorChangeResult::class, $judgement);
        self::assertTrue($judgement->isPending());
        self::assertSame($record->getKey(), $judgement->pending?->id);
        self::assertNotNull($judgement->credential);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertSame([SessionReturnedToPending::class, PasskeyAdded::class], $this->recordedClasses());

        $proof = self::adapterProof($identity, 'api', $record->getKey(), Purpose::SIGN_IN);

        self::assertTrue($this->sessions()->satisfy($judgement->credential, $proof, self::requestClient())->isSignedIn());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * A gate that removes a passkey factor through the factor package's own
     * removal (`factorRemoved()` for its factor) answers that removal as its
     * completion, which the passkey's removal hands back as it is: the current
     * session, short of a further factor without that factor, returns to
     * pending, the completion carrying its new pending credential, which takes
     * another factor. A delete of the passkey the gate itself makes, an
     * injected conflict in the same transaction found by the removal's own
     * delete, rolls the return back with the rest, the passkey's row included,
     * so the session stays active, nothing is reported and no completion is
     * answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGateThatRemovesThePasskeysFactorHandsItsCompletionBackWithTheRemoval(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $record = $this->sessions()->satisfy(
            $pending->credential,
            self::adapterProof($identity, 'api', $pending->pending->id, Purpose::SIGN_IN),
            self::requestClient(),
        )->session?->record;

        self::assertNotNull($record);

        $concurrent = new \ArrayObject(['delete' => true]);

        $removing = static function (string $id) use ($identity, $record, $concurrent): FactorRemoval {
            $removal = Auth::sessions('api')->factorRemoved($identity, 'factor-1', $record);

            if ($concurrent['delete'] === true) {
                DB::table('passkeys')->where('id', $id)->delete();
            }

            return $removal;
        };

        app()->instance(PasskeyFactorGate::class, new RecordingPasskeyFactorGate(onRemoving: $removing));

        $this->recordEvents([PasskeyRemoved::class, SessionReturnedToPending::class]);

        $missed = Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient());

        self::assertFalse($missed->isRemoved());
        self::assertNull($missed->completion);
        self::assertSame(1, Passkey::query()->count());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertSame([], $this->recorded);

        $concurrent['delete'] = false;

        $removal    = Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient());
        $completion = $removal->completion;

        self::assertTrue($removal->isRemoved());
        self::assertInstanceOf(FactorRemoval::class, $completion);
        self::assertTrue($completion->isPending());
        self::assertSame($record->getKey(), $completion->pending?->id);
        self::assertNotNull($completion->credential);
        self::assertSame(0, Passkey::query()->count());
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertSame([SessionReturnedToPending::class, PasskeyRemoved::class], $this->recordedClasses());

        $proof = self::adapterProof($identity, 'api', $record->getKey(), Purpose::SIGN_IN);

        self::assertTrue($this->sessions()->satisfy($completion->credential, $proof, self::requestClient())->isSignedIn());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * Inside the removal's transaction the gate is asked first, with the
     * passkey's id and canonical credential id: a gate that refuses throws,
     * keeping the passkey and reporting nothing; one that lets it go ahead
     * removes it, reported once, and the removal hands back the completion it
     * answered, as it is; a delete of the passkey the gate itself makes, an
     * injected conflict in the same transaction, rolls the gate's work back and
     * is answered not removed, the completion dropped with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorGateIsAskedBeforeARemoval(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);
        $stored   = Passkey::query()->sole();

        app()->instance(PasskeyFactorGate::class, new RecordingPasskeyFactorGate(onRemoving: static function (): never {
            throw new \RuntimeException('The last factor.');
        }));

        $this->recordEvents([PasskeyRemoved::class]);

        try {
            Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient());

            self::fail('The refusal did not reach the caller.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The last factor.', $exception->getMessage());
        }

        self::assertSame(1, Passkey::query()->count());
        self::assertSame([], $this->recorded);

        $concurrent = new RecordingPasskeyFactorGate(onRemoving: static function (string $id): object {
            DB::table('integration_identities')->update(['email' => 'changed@example.test']);
            DB::table('passkeys')->where('id', $id)->delete();

            return new \stdClass;
        });

        app()->instance(PasskeyFactorGate::class, $concurrent);

        $missed = Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient());

        self::assertFalse($missed->isRemoved());
        self::assertNull($missed->completion);
        self::assertSame(1, Passkey::query()->count());
        self::assertSame('ada@example.test', DB::table('integration_identities')->value('email'));
        self::assertSame([], $this->recorded);

        $completion = new \stdClass;
        $gate       = new RecordingPasskeyFactorGate(onRemoving: static fn (): object => $completion);

        app()->instance(PasskeyFactorGate::class, $gate);

        $removal = Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient());

        self::assertTrue($removal->isRemoved());
        self::assertSame($completion, $removal->completion);
        self::assertSame(0, Passkey::query()->count());
        self::assertSame([[$identity, 'api', $passkey->id, $stored->credential_id]], array_map(static fn (array $removal): array => array_values($removal), $gate->removals));
        self::assertSame([PasskeyRemoved::class], $this->recordedClasses());
    }

    /**
     * A factor ceremony allows only those of the identity's passkeys whose
     * credential id the factor package names, compared exactly: another passkey
     * of the identity, another identity's, and an id that differs only in case
     * are left out, and with none left nothing is handed out or written. The
     * options list the passkeys allowed, and give the browser the challenge's
     * lifetime in milliseconds. The challenge keeps the binding and asks for
     * user verification, or only prefers it when the factor package says so.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorCeremonyAllowsOnlyTheCredentialsNamed(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        $this->registerPasskey($identity);

        $mine = $this->authenticator()->lastCredentialId();

        $this->registerPasskey($identity);

        $second = $this->authenticator()->lastCredentialId();

        $this->registerPasskey($other);

        $theirs   = $this->authenticator()->lastCredentialId();
        $passkeys = Auth::passkeys('api');
        $binding  = self::factorBinding($identity);
        $options  = $passkeys->factorOptions($identity, $binding, [$mine, $theirs, self::caseFlipped($second)]);

        self::assertNotNull($options);
        self::assertSame([$mine], array_column((array) $options->options['allowCredentials'], 'id'));
        self::assertSame('required', $options->options['userVerification']);

        $challenge = PasskeyChallenge::query()->sole();

        self::assertSame(['factor', self::FACTOR_SESSION, 'step_up'], [$challenge->purpose, $challenge->session_id, $challenge->binding_purpose]);
        $preferred = $passkeys->factorOptions($identity, $binding, [$second], false)?->options;

        self::assertSame('preferred', $preferred['userVerification'] ?? null);
        self::assertIsArray($preferred['allowCredentials'] ?? null);
        self::assertTrue(array_is_list($preferred['allowCredentials']));
        self::assertSame([$second], array_column($preferred['allowCredentials'], 'id'));
        self::assertSame(300000, $preferred['timeout'] ?? null);
        self::assertNull($passkeys->factorOptions($identity, $binding, [$theirs]));
        self::assertNull($passkeys->factorOptions($identity, $binding, []));
        self::assertSame(2, PasskeyChallenge::query()->count());
    }

    /**
     * Rows of `[credential ids]` a factor ceremony refuses: an id with padding,
     * the standard alphabet, one that is not canonical, an empty one, and one
     * that is not a string.
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideMalformedCredentialIds(): iterable
    {
        yield 'padded' => [['YWJj=']];
        yield 'the standard alphabet' => [['ab+/']];
        yield 'not canonical' => [['YWJ']];
        yield 'empty' => [['']];
        yield 'not a string' => [[42]];
    }

    /**
     * A credential id that is not canonical unpadded base64url, or a binding
     * that does not name the identity, the guard and a session, is a
     * programming error, refused before anything is written.
     *
     * @param  array<array-key, mixed>  $ids
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedCredentialIds')]
    public function testAFactorCeremonyRefusesMalformedCredentialIds(array $ids): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        try {
            Auth::passkeys('api')->factorOptions($identity, self::factorBinding($identity), [$this->authenticator()->lastCredentialId(), ...$ids]);

            self::fail('A malformed credential id was taken.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('canonical unpadded base64url', $exception->getMessage());
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * Rows of `[binding]` a factor ceremony refuses: one for another identity,
     * another guard, no session, an empty session, and a session longer than
     * 255 characters.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Identity): \SineMacula\Laravel\Authentication\Proofs\ProofBinding}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideForeignBindings(): iterable
    {
        yield 'another identity' => [static fn (Identity $identity, Identity $other): ProofBinding => new ProofBinding($other, 'api', self::FACTOR_SESSION, Purpose::STEP_UP)];
        yield 'another guard' => [static fn (Identity $identity): ProofBinding => new ProofBinding($identity, 'admin', self::FACTOR_SESSION, Purpose::STEP_UP)];
        yield 'no session' => [static fn (Identity $identity): ProofBinding => new ProofBinding($identity, 'api', null, Purpose::STEP_UP)];
        yield 'an empty session' => [static fn (Identity $identity): ProofBinding => new ProofBinding($identity, 'api', '', Purpose::STEP_UP)];
        yield 'a session too long' => [static fn (Identity $identity): ProofBinding => new ProofBinding($identity, 'api', str_repeat('s', 256), Purpose::STEP_UP)];
    }

    /**
     * A binding that does not name the identity, the guard and a session of at
     * most 255 characters is a programming error, refused before anything is
     * written.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Identity): \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideForeignBindings')]
    public function testAFactorCeremonyRefusesABindingThatIsNotItsOwn(\Closure $binding): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        $this->registerPasskey($identity);

        try {
            Auth::passkeys('api')->factorOptions($identity, $binding($identity, $other), [$this->authenticator()->lastCredentialId()]);

            self::fail('A foreign binding was taken.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A passkey ceremony\'s binding must name the identity it is for, the guard [api] and a session.', $exception->getMessage());
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * A factor ceremony's session is measured in characters, not bytes: one of
     * 255 multibyte characters is taken.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorCeremonyMeasuresItsSessionInCharacters(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $binding = new ProofBinding($identity, 'api', str_repeat('é', 255), Purpose::STEP_UP);

        self::assertNotNull(Auth::passkeys('api')->factorOptions($identity, $binding, [$this->authenticator()->lastCredentialId()]));
    }

    /**
     * A factor challenge answers only the binding it was handed out for:
     * another session's or another purpose's verification of it is refused as
     * `passkey_challenge_invalid`, as a replay is, and a verification whose
     * binding names another identity or guard is a programming error.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorChallengeAnswersOnlyItsBinding(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $passkeys = Auth::passkeys('api');

        $others = [
            new ProofBinding($identity, 'api', 'another-session', Purpose::STEP_UP),
            new ProofBinding($identity, 'api', self::FACTOR_SESSION, Purpose::SIGN_IN),
        ];

        foreach ($others as $binding) {
            $options = self::factorCeremony($passkeys, $identity);
            $answer  = $this->authenticator()->get($options->options);

            self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, $passkeys->verifyFactor($identity, $binding, $options->challengeId, $answer, self::requestClient())->reason);
        }

        $options = self::factorCeremony($passkeys, $identity);
        $answer  = $this->authenticator()->get($options->options);

        self::assertTrue($passkeys->verifyFactor($identity, self::factorBinding($identity), $options->challengeId, $answer, self::requestClient())->isVerified());
        self::assertSame(
            FailureReason::PASSKEY_CHALLENGE_INVALID,
            $passkeys->verifyFactor($identity, self::factorBinding($identity), $options->challengeId, $answer, self::requestClient())->reason,
        );

        $this->expectException(\InvalidArgumentException::class);

        $passkeys->verifyFactor($identity, self::factorBinding($identity, 'admin'), $options->challengeId, $answer, self::requestClient());
    }

    /**
     * A passkey of the identity's that the challenge did not allow is refused
     * as `invalid_credentials`, and its count is not touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyTheChallengeDidNotAllowIsRefused(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $allowed = $this->authenticator()->lastCredentialId();

        $this->registerPasskey($identity);

        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->factorOptions($identity, self::factorBinding($identity), [$allowed]);

        self::assertNotNull($options);

        $answer = $this->authenticator()->get($options->options, $this->authenticator()->lastCredentialId());

        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $passkeys->verifyFactor($identity, self::factorBinding($identity), $options->challengeId, $answer, self::requestClient())->reason,
        );
        self::assertSame([0, 0], Passkey::query()->orderBy('created_at')->pluck('sign_count')->all());
    }

    /**
     * A verified factor reports what its assertion showed, never what the
     * ceremony asked for: under preferred user verification an authenticator
     * that does not verify the user is accepted and reported as unverified,
     * while a ceremony that requires it refuses it; backup flags are the
     * assertion's; a counter that stays at zero is accepted again and again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedFactorReportsWhatItsAssertionShowed(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $stored        = Passkey::query()->sole();
        $passkeys      = Auth::passkeys('api');
        $authenticator = $this->authenticator();
        $id            = $authenticator->lastCredentialId();

        $authenticator->userVerified = false;
        $authenticator->backedUp     = false;
        $authenticator->counterStep  = 0;

        $required = $passkeys->factorOptions($identity, self::factorBinding($identity), [$id]);

        self::assertNotNull($required);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, self::verifyPasskeyFactor($identity, $required->challengeId, $authenticator->get($required->options))->reason);

        foreach ([1, 2] as $use) {
            self::freezeAt($this->now->addSeconds($use));

            $preferred = $passkeys->factorOptions($identity, self::factorBinding($identity), [$id], false);

            self::assertNotNull($preferred);

            $assertion = $passkeys->verifyFactor(
                $identity,
                self::factorBinding($identity),
                $preferred->challengeId,
                $authenticator->get($preferred->options),
                self::requestClient(),
            )->assertion;

            self::assertNotNull($assertion);
            self::assertSame([$stored->id, $id], [$assertion->passkeyId, $assertion->credentialId]);
            self::assertEquals(new ObservedProperties(true, false, true, false, true), $assertion->observed);
            self::assertTrue($assertion->assertedAt->equalTo($this->now->addSeconds($use)));
            self::assertSame($stored->id, $assertion->passkey->id);
            self::assertFalse($assertion->passkey->backedUp);
        }

        self::assertSame(0, Passkey::query()->sole()->sign_count);
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
     * Move the frozen clock.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private static function freezeAt(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);
    }

    /**
     * Store a copy of the passkey for an identity of another type that has the
     * same id, on the same relying party, and return the copy's id.
     *
     * @param  string  $id
     * @return string
     */
    private static function passkeyOfAnotherType(string $id): string
    {
        $row  = (array) DB::table('passkeys')->where('id', $id)->first();
        $copy = (string) Str::uuid();

        DB::table('passkeys')->insert([...$row, 'id' => $copy, 'credential_id_hash' => hash('sha256', $copy), 'authenticatable_type' => MachineClient::class]);

        return $copy;
    }

    /**
     * The credential id with the case of one letter flipped, short of the last
     * character (whose unused bits must stay zero), so it is still canonical
     * and differs only in case.
     *
     * @param  string  $credentialId
     * @return string
     */
    private static function caseFlipped(string $credentialId): string
    {
        $at = strcspn($credentialId, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');

        self::assertLessThan(strlen($credentialId) - 1, $at);

        $flipped = $credentialId;

        $flipped[$at] = ctype_upper($credentialId[$at]) ? strtolower($credentialId[$at]) : strtoupper($credentialId[$at]);

        return $flipped;
    }
}
