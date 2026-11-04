<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Context\ScriptedContributor;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\StubBareSession;

/**
 * Feature tests of what a contributor to the authentication context is given:
 * the bound instances as they are, the session's external provenance, read on
 * the write connection the first time it is asked for and never again, and the
 * counting proofs and first factor of the session it was given (never the
 * request's), read each time they are asked for, only while that session is
 * still the application's live, active session of a person, and locked and read
 * current inside a transaction as the session service's reads are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContributionSubject::class)]
final class ContributionSubjectTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

    /** @var int Reads of the provenance table since counting began. */
    private int $provenanceReads = 0;

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
     * A session an external provider established has its provenance read once,
     * on the first ask, as the session records it, the adapter's provider
     * context with it in the same read; asked again it is the same provenance,
     * read from nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalSessionsProvenanceIsReadOnceOnTheFirstAsk(): void
    {
        $identity = $this->seedIdentity();
        $context  = new ProviderContext(['protocol' => 'saml', 'link' => ['made' => 'explicitly']]);
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity, 'connection-7', 'link-9', tenantId: 'tenant-3', providerContext: $context))->session;

        self::assertNotNull($session);

        $subject = self::subject($identity, $session->record);

        $this->countProvenanceReads();

        self::assertSame(0, $this->provenanceReads);

        $provenance = $subject->provenance();

        self::assertNotNull($provenance);
        self::assertSame(['connection-7', 'tenant-3', 'link-9'], [$provenance->connectionId, $provenance->tenantId, $provenance->linkId]);
        self::assertSame(['protocol' => 'saml', 'link' => ['made' => 'explicitly']], $provenance->providerContext?->toArray());
        self::assertSame($provenance, $subject->provenance());
        self::assertSame(1, $this->provenanceReads);
    }

    /**
     * A session no external provider established has none, read once; without a
     * session, or with one that is not an Eloquent session (a plain session, or
     * an Eloquent model that is not one), there is none and nothing is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutProvenanceHasNone(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->countProvenanceReads();

        $password = self::subject($identity, $session->record);

        self::assertNull($password->provenance());
        self::assertNull($password->provenance());
        self::assertSame(1, $this->provenanceReads);

        self::assertNull(self::subject($identity, null)->provenance());
        self::assertNull(self::subject($identity, new PlainSessionFixture((string) IdentifierCoercion::stringify($session->record->getKey())))->provenance());
        self::assertNull(self::subject($identity, new StubBareSession(['id' => IdentifierCoercion::stringify($session->record->getKey())]))->provenance());
        self::assertSame(1, $this->provenanceReads);
    }

    /**
     * A subject built inside a request authenticated with one session reads the
     * session it was given, its own step-up and first factor, and never the
     * request's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSubjectReadsTheSessionItWasGivenNeverTheRequests(): void
    {
        $this->seedIdentity();

        $request = $this->signedIn();
        $given   = $this->signedIn();

        self::recordProof($given->record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));

        Route::middleware('auth:api')->get('/subjects/{session}', static function (string $session): array {

            $bound = Auth::identity();

            assert($bound instanceof IntegrationIdentity);

            $subject = self::subject($bound, SessionLookup::find($session));

            return [
                'request' => IdentifierCoercion::stringify(Auth::session()?->getSessionIdentifier()),
                'proofs'  => array_map(static fn (RecordedProof $proof): string => $proof->id, $subject->proofs()),
                'first'   => $subject->firstFactor()?->id,
            ];
        });

        $answer = $this->withToken($request->tokens->accessToken->reveal())->getJson('/subjects/' . IdentifierCoercion::stringify($given->record->getKey()))->assertOk();
        $stored = DB::table('authentication_proofs')->where('session_id', $given->record->getKey())->orderByDesc('authenticated_at')->pluck('id')->all();

        $answer->assertExactJson(['request' => IdentifierCoercion::stringify($request->record->getKey()), 'proofs' => $stored, 'first' => $stored[1]]);
    }

    /**
     * Without a session, or with one that is not an Eloquent session, there are
     * no proofs and no first factor, and nothing is read, the session model not
     * even resolved; the limit is checked first, whatever the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAnEloquentSessionThereAreNoProofsAndNothingIsRead(): void
    {
        $identity = $this->seedIdentity();
        $id       = (string) IdentifierCoercion::stringify($this->signedIn()->record->getKey());

        foreach ([null, new PlainSessionFixture($id, $this->now->addHour()), new StubBareSession(['id' => $id])] as $session) {
            $subject = self::subject($identity, $session);

            self::assertSame([], self::statementsDuring(static function () use ($subject): void {
                self::assertSame([], $subject->proofs());
                self::assertNull($subject->firstFactor());
            }));

            foreach ([0, 201] as $limit) {
                try {
                    $subject->proofs(limit: $limit);

                    self::fail('A limit of ' . $limit . ' was taken.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame('A contribution subject returns between 1 and 200 proofs at a time.', $exception->getMessage());
                }
            }
        }

        self::assertCount(1, self::subject($identity, SessionLookup::find($id))->proofs(limit: 1));
        self::assertCount(1, self::subject($identity, SessionLookup::find($id))->proofs(limit: 200));

        config()->set('authentication.session.model', IntegrationIdentity::class);

        self::assertSame([], self::subject($identity, null)->proofs());
        self::assertNull(self::subject($identity, null)->firstFactor());
    }

    /**
     * A subject whose session is revoked, pending, past its idle deadline,
     * another application's or a machine's, or whose key another sign-in of the
     * same owner reused, answers no proofs and no first factor, while the
     * session's key holds its proofs still.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionNoLongerTheApplicationsLiveSessionAnswersNothing(): void
    {
        $identity = $this->seedIdentity();
        $record   = $this->signedIn()->record;
        $key      = $record->getKey();
        $answers  = static fn (ContributionSubject $subject): array => [$subject->proofs(), $subject->firstFactor()];

        self::assertSame([[], null], $answers(self::subject($identity, $record, 'admin')));

        $states = [
            ['revoked_at' => $this->now, 'revoked_reason' => 'revoked'],
            ['revoked_at' => null, 'revoked_reason' => null, 'status' => 'pending'],
            ['status' => 'active', 'idle_expires_at' => $this->now],
            ['idle_expires_at' => $this->now->addHour(), 'authenticatable_type' => MachineClient::class],
        ];

        foreach ($states as $state) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            self::assertSame([[], null], $answers(self::subject($identity, $record)));
        }

        DB::table('authentication_sessions')->where('id', $key)->update([
            'authenticatable_type' => $record->getAttribute('authenticatable_type'),
            'generation'           => (string) Str::uuid7(),
        ]);

        $reused = SessionLookup::find($key);

        self::assertNotNull($reused);

        ProofWriter::clear($reused);
        ProofWriter::record($reused, 'api', SignInProof::unattested('passkey', $this->now)->firstFactor());

        self::assertSame([[], null], $answers(self::subject($identity, $record)));
        self::assertSame('passkey', self::subject($identity, $reused)->firstFactor()?->method);
        self::assertSame(1, DB::table('authentication_proofs')->where('session_id', $key)->count());
    }

    /**
     * Each ask reads again, the session and then its proofs: a proof recorded
     * between two asks is in the second answer, and a first factor voided
     * between two asks is gone from it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachAskReadsAgain(): void
    {
        $identity = $this->seedIdentity();
        $record   = $this->signedIn()->record;
        $subject  = self::subject($identity, $record);

        $proofs = [];

        self::assertCount(2, self::statementsDuring(static function () use ($subject, &$proofs): void {
            $proofs = $subject->proofs();
        }));
        self::assertCount(1, $proofs);
        self::assertCount(2, self::statementsDuring(static fn (): ?RecordedProof => $subject->firstFactor()));

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $subject->proofs()));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $subject->proofs($this->now->addMinute())));
        self::assertSame([ProofKind::FIRST_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $subject->proofs(kinds: [ProofKind::FIRST_FACTOR])));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $subject->proofs(limit: 1)));
        self::assertNotNull($subject->firstFactor());

        DB::table('authentication_proofs')->where('kind', ProofKind::FIRST_FACTOR->value)->update(['voided_at' => $this->now]);

        self::assertNull($subject->firstFactor());
        self::assertCount(2, self::statementsDuring(static fn (): ?RecordedProof => $subject->firstFactor()));
    }

    /**
     * A registered contributor's keys come from its subject's proofs and first
     * factor as of its own call: a step-up recorded after the package's own
     * keys were worked out, before the contributor asks, is among them, while
     * the package's `mfa` key, worked out before, does not show it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContributorReadsTheProofsAsOfItsCall(): void
    {
        $this->seedIdentity();

        $signedIn = $this->signedIn();
        $now      = $this->now;

        $contributor = new ScriptedContributor(static function (ContributionSubject $subject) use ($now): array {

            $session = $subject->session;

            assert($session instanceof Model && $session instanceof EloquentSession);

            self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $now->addMinute(), ['otp'], new Evaluation(true, true));

            return [
                'kinds'        => array_map(static fn (RecordedProof $proof): string => $proof->kind->value, $subject->proofs()),
                'first_method' => $subject->firstFactor()?->method,
            ];
        });

        app()->instance('tests.context.mfa', $contributor);
        app(ContextContributors::class)->register('mfa', 'tests.context.mfa');

        Route::middleware('auth:api')->get('/context', static fn (): array => ['context' => Auth::context()?->toArray()]);

        $context = $this->withToken($signedIn->tokens->accessToken->reveal())->getJson('/context')->assertOk();

        $context->assertJsonPath('context.mfa', ['kinds' => ['additional_factor', 'first_factor'], 'first_method' => 'password']);
        $context->assertJsonPath('context.authentication.mfa', false);
    }

    /**
     * Inside a transaction on the session model's connection the subject locks
     * its session's row before reading its proofs current, as the session
     * service's reads do; outside one it reads both plainly.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideATransactionTheSubjectLocksAsTheServiceDoes(): void
    {
        $identity = $this->seedIdentity();
        $subject  = self::subject($identity, $this->signedIn()->record);

        self::markSharedLocks();

        $locks = static fn (\Closure $read): array => array_map(
            static fn (string $sql): array => [self::locksForUpdate($sql), self::sharesLock($sql)],
            self::statementsDuring($read),
        );

        foreach ([static fn (): array => $subject->proofs(), static fn (): ?RecordedProof => $subject->firstFactor()] as $read) {
            self::assertSame([[true, false], [false, self::takesSharedLocks()]], $locks(static fn (): mixed => DB::transaction($read)));
            self::assertSame([[false, false], [false, false]], $locks($read));
        }
    }

    /**
     * Register the guards and providers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * What a contributor is given for the identity acting as itself in the
     * session, on the application given.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Context\ContributionSubject
     */
    private static function subject(IntegrationIdentity $identity, ?Session $session, string $application = 'api'): ContributionSubject
    {
        $id      = IdentifierCoercion::stringify($identity->getKey());
        $context = new AuthenticationContext(
            SubjectType::PERSON,
            'identity',
            $id,
            'identity',
            $id,
            null,
            null,
            $application,
            null,
            [],
            null,
            false,
            false,
            false,
            null,
            null,
            null,
            null,
        );

        return new ContributionSubject($context, $identity, $identity, null, $session);
    }

    /**
     * A session the seeded identity signed in to on the guard with its
     * password.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Count the reads of the provenance table from now on.
     *
     * @return void
     */
    private function countProvenanceReads(): void
    {
        $this->provenanceReads = 0;

        DB::listen(function (QueryExecuted $query): void {

            if (!str_contains($query->sql, 'authentication_provenance')) {
                return;
            }

            $this->provenanceReads++;
        });
    }
}
