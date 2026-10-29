<?php

declare(strict_types = 1);

namespace Tests\Integration\Verification;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubVerifiableIdentity;

/**
 * Integration tests for verifying an identity's identifier once a proof of it
 * has been checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierVerifier::class)]
#[CoversClass(IdentifierVerified::class)]
final class IdentifierVerifierTest extends TestCase
{
    use InteractsWithVerifiableIdentities;

    /** @var string Guard the verifications are made for. */
    private const string GUARD = 'api';

    /**
     * Create the identities table and freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2027-03-01 08:30:00'));

        self::createVerifiableIdentitiesTable();
    }

    /**
     * Drop the identities table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('verifiable_identities');
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The outcomes, by value.
     *
     * @return void
     */
    public function testOutcomes(): void
    {
        $values = array_map(static fn (IdentifierVerification $outcome): string => $outcome->value, IdentifierVerification::cases());

        self::assertSame(['verified', 'already_verified', 'mismatch'], $values);
    }

    /**
     * Proving the current identifier, in any casing the normaliser folds,
     * verifies it and dispatches `IdentifierVerified` once with the guard, the
     * identity, the type and the client; nothing is signed in.
     *
     * @return void
     */
    public function testProvingTheCurrentIdentifierVerifiesIt(): void
    {
        Event::fake([IdentifierVerified::class]);

        $identity = self::seedVerifiableIdentity();
        $client   = new ClientContext('203.0.113.7', 'Mail/1.0');

        self::assertSame(IdentifierVerification::VERIFIED, $this->verifier()->verify(self::GUARD, $identity, 'email', ' BEN@Example.com ', $client));
        self::assertNotNull(DB::table('verifiable_identities')->value('email_verified_at'));

        Event::assertDispatchedTimes(IdentifierVerified::class, 1);
        Event::assertDispatched(IdentifierVerified::class, static fn (IdentifierVerified $event): bool => $event->context->guard === self::GUARD
            && $event->context->identity                                                                                         === $identity
            && $event->type                                                                                                      === 'email'
            && $event->context->client                                                                                           === $client);

        self::assertFalse(Auth::guard(self::GUARD)->hasUser());
        self::assertSame(0, DB::table('devices')->count());
    }

    /**
     * A verification whose caller names no client reports the client of the
     * request being served.
     *
     * @return void
     */
    public function testAVerificationWithoutAClientReportsTheServedRequest(): void
    {
        Event::fake([IdentifierVerified::class]);

        $this->app?->instance('request', Request::create('/verify', 'GET', server: ['REMOTE_ADDR' => '198.51.100.4', 'HTTP_USER_AGENT' => 'Served/1.0']));

        self::assertSame(IdentifierVerification::VERIFIED, $this->verifier()->verify(self::GUARD, self::seedVerifiableIdentity(), 'email', 'ben@example.com'));

        Event::assertDispatched(IdentifierVerified::class, static fn (IdentifierVerified $event): bool => $event->context->client->ip === '198.51.100.4'
            && $event->context->client->userAgent                                                                                     === 'Served/1.0');
    }

    /**
     * Verifying again reports the identifier already verified and dispatches
     * nothing, whether the identity in hand knows it is verified or not.
     *
     * @return void
     */
    public function testVerifyingAgainReportsAlreadyVerified(): void
    {
        $identity = self::seedVerifiableIdentity();
        $stale    = VerifiableIdentity::query()->findOrFail($identity->getKey());

        $this->verifier()->verify(self::GUARD, $identity, 'email', 'ben@example.com');

        Event::fake([IdentifierVerified::class]);

        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, $this->verifier()->verify(self::GUARD, $identity, 'email', 'ben@example.com'));
        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, $this->verifier()->verify(self::GUARD, $stale, 'email', 'ben@example.com'));

        Event::assertNotDispatched(IdentifierVerified::class);
    }

    /**
     * A proof for another identifier, a value the normaliser rejects, or an
     * identity with no identifier of the type is a mismatch: nothing is
     * recorded or dispatched.
     *
     * @return void
     */
    public function testProvingAnotherIdentifierIsAMismatch(): void
    {
        Event::fake([IdentifierVerified::class]);

        $identity  = self::seedVerifiableIdentity();
        $phoneless = self::seedVerifiableIdentity('other@example.com');

        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, $identity, 'email', 'old@example.com'));
        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, $identity, 'email', '   '));
        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, $phoneless, 'phone', '+447700900123'));
        self::assertNull(DB::table('verifiable_identities')->where('id', $identity->getKey())->value('email_verified_at'));

        Event::assertNotDispatched(IdentifierVerified::class);
    }

    /**
     * An identifier's canonical form is its type's normal form when a
     * normaliser is registered, `null` when the normaliser rejects it, and the
     * identifier as given otherwise.
     *
     * @return void
     */
    public function testCanonicalFormFollowsTheTypesNormaliser(): void
    {
        self::assertSame('ben@example.com', $this->verifier()->canonical('email', ' Ben@Example.COM'));
        self::assertNull($this->verifier()->canonical('email', '  '));
        self::assertSame(' Member-42', $this->verifier()->canonical('member_number', ' Member-42'));
    }

    /**
     * A type without a registered normaliser is compared exactly.
     *
     * @return void
     */
    public function testTypeWithoutANormaliserIsComparedExactly(): void
    {
        $identity = self::seedVerifiableIdentity('ben@example.com', 'Member-42');

        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, $identity, 'phone', 'member-42'));
        self::assertSame(IdentifierVerification::VERIFIED, $this->verifier()->verify(self::GUARD, $identity, 'phone', 'Member-42'));
    }

    /**
     * An identifier changed after the identity was loaded, while the proof was
     * checked, is not verified, and is reported as a mismatch rather than as
     * verified before.
     *
     * @return void
     */
    public function testIdentifierChangedMeanwhileIsAMismatch(): void
    {
        Event::fake([IdentifierVerified::class]);

        $identity = self::seedVerifiableIdentity();

        DB::table('verifiable_identities')->update(['email' => 'new@example.com', 'email_verified_at' => '2027-02-01 00:00:00']);

        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, $identity, 'email', 'ben@example.com'));

        DB::table('verifiable_identities')->delete();

        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, $identity, 'email', 'ben@example.com'));

        Event::assertNotDispatched(IdentifierVerified::class);
    }

    /**
     * Inside a transaction on the identity's connection, the event waits for
     * the commit, and a rolled-back verification is never reported.
     *
     * @return void
     */
    public function testEventWaitsForTheCommitAndNeverReportsARollback(): void
    {
        $events = [];

        Event::listen(IdentifierVerified::class, static function (IdentifierVerified $event) use (&$events): void {
            $events[] = $event->type;
        });

        $identity = self::seedVerifiableIdentity('ben@example.com', '+447700900123');

        DB::transaction(function () use ($identity, &$events): void {
            $this->verifier()->verify(self::GUARD, $identity, 'email', 'ben@example.com');

            self::assertSame([], $events);
        });

        self::assertSame(['email'], $events);

        DB::beginTransaction();
        $this->verifier()->verify(self::GUARD, $identity, 'phone', '+447700900123');
        DB::rollBack();

        self::assertSame(['email'], $events);
        self::assertNull(DB::table('verifiable_identities')->value('phone_verified_at'));
    }

    /**
     * An identity that is not an Eloquent model is verified through its own
     * contract methods, and its event is dispatched at once.
     *
     * @return void
     */
    public function testIdentityThatIsNotAModelIsVerifiedThroughItsContract(): void
    {
        Event::fake([IdentifierVerified::class]);

        $identity = new StubVerifiableIdentity(7, ['email' => 'ben@example.com']);

        DB::transaction(function () use ($identity): void {
            self::assertSame(IdentifierVerification::VERIFIED, $this->verifier()->verify(self::GUARD, $identity, 'email', 'BEN@example.com'));

            Event::assertDispatchedTimes(IdentifierVerified::class, 1);
        });

        self::assertTrue($identity->hasVerifiedIdentifier('email'));
        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, $this->verifier()->verify(self::GUARD, $identity, 'email', 'ben@example.com'));
        self::assertSame(IdentifierVerification::MISMATCH, $this->verifier()->verify(self::GUARD, new StubVerifiableIdentity(8, []), 'email', 'ben@example.com'));
    }

    /**
     * An identity that cannot verify identifiers, or a malformed type, is a
     * misconfiguration, reported rather than read as a mismatch.
     *
     * @return void
     */
    public function testMisconfigurationIsReported(): void
    {
        try {
            $this->verifier()->verify(self::GUARD, new PlainIdentityFixture(1), 'email', 'ben@example.com');
            self::fail('Expected an identity without the contract to be reported.');
        } catch (\LogicException $e) {
            self::assertSame(PlainIdentityFixture::class . ' cannot verify identifiers: it does not implement ' . HasVerifiableIdentifiers::class . '.', $e->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier type [e-mail] must be');

        $this->verifier()->verify(self::GUARD, self::seedVerifiableIdentity(), 'e-mail', 'ben@example.com');
    }

    /**
     * Configure the guard over the identities.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'verifiable']);
        $config->set('auth.providers.verifiable', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
    }

    /**
     * The verifier.
     *
     * @return \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier
     */
    private function verifier(): IdentifierVerifier
    {
        $verifier = $this->app?->make(IdentifierVerifier::class);

        self::assertInstanceOf(IdentifierVerifier::class, $verifier);

        return $verifier;
    }
}
