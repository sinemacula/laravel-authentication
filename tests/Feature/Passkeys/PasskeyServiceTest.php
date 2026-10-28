<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyOwner;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests for the passkey service `Auth::passkeys()` returns, and for
 * registering a passkey through it: the options a registration is handed, which
 * challenges it may answer, what it stores and reports, and what it refuses.
 * Its other ceremonies have tests of their own: `PasskeySignInTest`,
 * `PasskeySignInOptionsTest`, `PasskeyFactorTest` and `PasskeyManagementTest`.
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
    use InteractsWithMachineClients, InteractsWithPasskeys, InteractsWithRateLimits, InteractsWithSessions;

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
     * count, transports, backup state and name, and summarised without any of
     * the key material; `PasskeyAdded` reports it with the passkey's id and the
     * request's client.
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
        $summary = Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), 'Work laptop');

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
        self::assertSame($identity, $event->context->identity);
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

        Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), null, new ClientContext('198.51.100.4', 'Agent/2'));

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

        self::assertInstanceOf(PasskeySummary::class, Auth::passkeys('api')->register($identity, $options->challengeId, $answer));
    }

    /**
     * Rows of `[name given, name stored]`: a name is stored cleaned of NUL
     * bytes and invalid UTF-8, cut to 255 characters, and `null` when nothing
     * is left.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideNames(): iterable
    {
        yield from [
            'none'           => [null, null],
            'empty'          => ['', null],
            'a NUL byte'     => ["Lap\0top", 'Laptop'],
            'invalid UTF-8'  => ["Lap\xfftop", 'Lap?top'],
            'over 255 chars' => [str_repeat('é', 300), str_repeat('é', 255)],
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
        $summary  = Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), $name);

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

        Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options));

        self::assertSame([$first->user_handle], Passkey::query()->distinct()->pluck('user_handle')->all());

        $other = Auth::passkeys('api')->registrationOptions($this->seedIdentity('grace@example.test'), self::USER_NAME);

        self::assertNotSame($first->user_handle, ((array) $other->options['user'])['id']);
        self::assertSame([], $other->options['excludeCredentials']);
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
            'a sign-in challenge' => [static fn (): string => Auth::passkeys('api')->signInOptions()->challengeId],
            'a factor challenge'  => [static fn (self $test, Identity $identity): string => Auth::passkeys('api')->factorOptions($identity)->challengeId],
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

        $this->recordEvents([PasskeyAdded::class]);

        $answer = $this->authenticator()->create($options->options);

        self::assertSame(PasskeyRegistrationFailure::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $id, $answer));
        self::assertSame(0, Passkey::query()->count());
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

        self::assertInstanceOf(PasskeySummary::class, Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options)));
        $answer = $this->authenticator()->create($options->options);

        self::assertSame(PasskeyRegistrationFailure::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $options->challengeId, $answer));
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

        self::assertInstanceOf(PasskeySummary::class, Auth::passkeys('api')->register($identity, $live->challengeId, $this->authenticator()->create($live->options)));

        self::freezeAt($this->now->addSeconds(300));

        $answer = $this->authenticator()->create($expired->options);

        self::assertSame(PasskeyRegistrationFailure::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $expired->challengeId, $answer));
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

        self::assertSame(PasskeyRegistrationFailure::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, $options->challengeId, $answer));
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

        self::assertSame(PasskeyRegistrationFailure::RESPONSE_INVALID, Auth::passkeys('api')->register($identity, $malformed->challengeId, '{'));
        self::assertSame(PasskeyRegistrationFailure::RESPONSE_INVALID, Auth::passkeys('api')->register($identity, $foreign->challengeId, $wrongOrigin->create($foreign->options)));
        self::assertSame(PasskeyRegistrationFailure::RESPONSE_INVALID, Auth::passkeys('api')->register($identity, $assertion->challengeId, $assertionCredential));
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

            self::assertSame(PasskeyRegistrationFailure::ALREADY_REGISTERED, Auth::passkeys('api')->register($registrant, $options->challengeId, $answer));
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
            static fn (): mixed => Auth::passkeys('api')->register($machine, '0192f6b2-0000-7000-8000-000000000001', '{}'),
            static fn (): mixed => Auth::passkeys('api')->factorOptions($machine),
            static fn (): mixed => Auth::passkeys('api')->verifyFactor($machine, '0192f6b2-0000-7000-8000-000000000001', '{}'),
            static fn (): mixed => Auth::passkeys('api')->passkeys($machine),
            static fn (): mixed => Auth::passkeys('api')->remove($machine, '0192f6b2-0000-7000-8000-000000000001'),
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

        $options = Auth::passkeys('api')->signInOptions();

        self::assertSame([[], 'required'], [$options->options['allowCredentials'], $options->options['userVerification']]);
        self::assertSame([self::RP_ID, 300000], [$options->options['rpId'], $options->options['timeout']]);
        self::assertSame(32, strlen(VirtualAuthenticator::decode(VirtualAuthenticator::at($options->options, 'challenge'))));
        self::assertNotSame($options->options['challenge'], Auth::passkeys('api')->signInOptions()->options['challenge']);

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

        Auth::passkeys('api')->signInOptions();
        Auth::passkeys('api')->signInOptions();

        self::assertSame(2, self::counterHits('api', 'passkey_options', 'per_ip', self::CLIENT_IP));

        try {
            Auth::passkeys('api')->signInOptions();

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

        Auth::passkeys('api')->signInOptions();

        $this->expectException(ThrottleRequestsException::class);

        Auth::passkeys('api')->signInOptions();
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

        $options = Auth::passkeys('api')->factorOptions($identity);
        $own     = Passkey::query()->where('authenticatable_id', (string) $identity->id)->sole();

        self::assertSame([['type' => 'public-key', 'id' => $own->credential_id, 'transports' => ['internal', 'hybrid']]], $options->options['allowCredentials']);
        self::assertSame(['required', self::RP_ID], [$options->options['userVerification'], $options->options['rpId']]);

        $challenge = PasskeyChallenge::query()->findOrFail($options->challengeId);

        self::assertSame(['factor', (string) $identity->id], [$challenge->purpose, $challenge->authenticatable_id]);
    }

    /**
     * The identity's passkey verifies as a factor: `null`, its count and use
     * recorded, `PasskeyUsed` reported with the client given, and no failure
     * reported or attempt counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitysPasskeyVerifiesAsAFactor(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);
        $options  = Auth::passkeys('api')->factorOptions($identity);

        $this->recordEvents([PasskeyUsed::class, AuthenticationFailed::class]);

        $answer  = $this->authenticator()->get($options->options);
        $outcome = Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $answer, new ClientContext('198.51.100.9', 'Factor/1'));

        self::assertNull($outcome);
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

        $options  = Auth::passkeys('api')->factorOptions($identity);
        $response = $this->authenticator()->get($options->options);

        unset($response['response']['userHandle']);

        self::assertNull(Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, (string) json_encode($response)));
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

        $this->registerPasskey($other);

        $options = Auth::passkeys('api')->factorOptions($identity);

        $this->recordEvents([PasskeyUsed::class, AuthenticationFailed::class]);

        $answer = $this->authenticator()->get(['allowCredentials' => []] + $options->options);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $answer));
        self::assertSame(0, Passkey::query()->sole()->sign_count);
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

        $own      = Auth::passkeys('api')->factorOptions($identity);
        $response = $this->authenticator()->get($own->options);

        foreach ([Auth::passkeys('api')->factorOptions($other)->challengeId, $this->signInOptions()->challengeId, '0192f6b2-0000-7000-8000-000000000001'] as $challenge) {
            self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, Auth::passkeys('api')->verifyFactor($identity, $challenge, $response));
        }

        self::assertNull(Auth::passkeys('api')->verifyFactor($identity, $own->challengeId, $response));
        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, Auth::passkeys('api')->verifyFactor($identity, $own->challengeId, $response));
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

        $malformed = Auth::passkeys('api')->factorOptions($identity);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, Auth::passkeys('api')->verifyFactor($identity, $malformed->challengeId, '{}'));

        $this->authenticator()->userVerified = false;

        $unverified = Auth::passkeys('api')->factorOptions($identity);

        $answer = $this->authenticator()->get($unverified->options);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, Auth::passkeys('api')->verifyFactor($identity, $unverified->challengeId, $answer));
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

        $first = Auth::passkeys('api')->factorOptions($identity);

        self::assertNull(Auth::passkeys('api')->verifyFactor($identity, $first->challengeId, $this->authenticator()->get($first->options)));

        $this->authenticator()->setCounter($this->authenticator()->lastCredentialId(), 0);

        $again = Auth::passkeys('api')->factorOptions($identity);

        $answer = $this->authenticator()->get($again->options);

        self::assertSame(FailureReason::PASSKEY_COUNTER_REGRESSED, Auth::passkeys('api')->verifyFactor($identity, $again->challengeId, $answer));
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

        $options = Auth::passkeys('api')->factorOptions($identity);

        self::assertNull(Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $this->authenticator()->get($options->options)));
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
     * with the passkey's id and the client given; removing it again removes
     * nothing and reports nothing.
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

        self::assertTrue(Auth::passkeys('api')->remove($identity, $passkey->id, new ClientContext('198.51.100.3', 'Remover/1')));
        self::assertSame(0, Passkey::query()->count());

        $event = $this->recordedEvent(PasskeyRemoved::class);

        self::assertSame(['api', 'passkey', $passkey->id, (string) $identity->id, '198.51.100.3'], [
            $event->context->guard,
            $event->context->method,
            $event->context->credentialId,
            $event->context->identityId,
            $event->context->client->ip,
        ]);

        self::assertFalse(Auth::passkeys('api')->remove($identity, $passkey->id));
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

        self::assertFalse(Auth::passkeys('api')->remove($identity, $foreign->id));
        self::assertFalse(Auth::passkeys('api')->remove($identity, $namesakes));
        self::assertFalse(Auth::passkeys('api')->remove($identity, $elsewhere->id));
        self::assertFalse(Auth::passkeys('api')->remove($identity, '0192f6b2-0000-7000-8000-000000000001'));

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertFalse(Auth::passkeys('api')->remove($identity, 'not-a-uuid'));
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

        self::assertTrue(Auth::passkeys('api')->remove($identity, $removed->id));
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

        self::assertTrue(Auth::passkeys('api')->remove($identity, $passkey->id));
        self::assertSame([], $this->recorded);

        DB::rollBack();

        self::assertSame([], $this->recorded);
        self::assertSame(1, Passkey::query()->count());

        DB::transaction(static function () use ($identity, $passkey): void {
            Auth::passkeys('api')->remove($identity, $passkey->id);
        });

        self::assertSame([PasskeyRemoved::class], $this->recordedClasses());
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
}
