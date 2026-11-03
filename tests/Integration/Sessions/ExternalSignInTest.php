<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\TestCase;

/**
 * Integration tests for external sign-in against a real database, on whichever
 * engine the suite runs on: inside the adapter's own transaction the session,
 * its first proof and its provenance commit or roll back with it, the link
 * contract asked first, and the link's id is kept byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalSignIn::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SessionProofs::class)]
final class ExternalSignInTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

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
     * Inside the adapter's transaction the session, its proof and its
     * provenance are written there, and the reports and the guard's bind wait
     * for the commit; a rollback leaves none of them, reports nothing and binds
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSignInFollowsTheAdaptersTransaction(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity);

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionAuthenticated::class]);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->signInExternally($result)->isSignedIn());
        self::assertSame([], $this->recordedClasses());
        self::assertFalse(Auth::guard('api')->hasUser());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertFalse(Auth::guard('api')->hasUser());
        self::assertSame([0, 0, 0], [Session::query()->count(), SessionProof::query()->count(), SessionProvenance::query()->count()]);

        DB::beginTransaction();

        $session = $this->sessions()->signInExternally($result)->session;

        DB::commit();

        self::assertNotNull($session);
        self::assertSame([SessionCreated::class, SignedIn::class, SessionAuthenticated::class], $this->recordedClasses());
        self::assertSame($identity->getKey(), Auth::guard('api')->id());
        self::assertSame([1, 1, 1], [Session::query()->count(), SessionProof::query()->count(), SessionProvenance::query()->count()]);
    }

    /**
     * An exception from the link contract inside the adapter's transaction
     * reaches it with nothing of the sign-in written, so the adapter rolls back
     * or retries the whole transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptionFromTheLinkContractLeavesNothingWritten(): void
    {
        $failure = new \RuntimeException('The link store is down.');

        $this->externalLinks()->failWith($failure);

        try {
            DB::transaction(fn () => $this->sessions()->signInExternally(new ExternalResult('connection-7', self::ISSUER, 'subject-1')));

            self::fail('The link contract\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(0, DB::transactionLevel());
        self::assertSame([0, 0], [Session::query()->count(), SessionProvenance::query()->count()]);
    }

    /**
     * The link's id is recorded and read back byte for byte on every engine:
     * ids that differ only in case or by a trailing space are kept apart.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLinkIdIsKeptByteForByte(): void
    {
        $identity = $this->seedIdentity();
        $ids      = ['link-a', 'LINK-A', 'link-a ', str_repeat("\u{1F517}", 255)];
        $sessions = [];

        foreach ($ids as $index => $id) {
            $sessions[$id] = $this->sessions()->signInExternally($this->linkedResult($identity, linkId: $id, subject: "subject-{$index}"))->session?->record;
        }

        foreach ($sessions as $id => $record) {
            self::assertNotNull($record);
            self::assertSame($id, SessionProofs::provenance($record)?->linkId);
        }

        self::assertSame(1, SessionProvenance::query()->where('link_id', 'link-a')->count());
    }

    /**
     * The largest evidence the evidence takes, all of it outside ASCII and
     * outside the basic plane, is written with the first proof and the
     * provenance on every engine, and reads back unchanged from both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLargestEvidenceIsStoredWhole(): void
    {
        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $now      = CarbonImmutable::now();
        $methods  = [...array_fill(0, 21, str_repeat("\u{1F600}", 255)), str_repeat("\u{1F600}", 80)];
        $stored   = ['methods' => $methods, 'context' => '', 'authenticated_at' => $now->utc()->toIso8601String()];
        $room     = ExternalEvidence::STORED_MAX_BYTES - strlen((string) json_encode($stored));
        $evidence = new ExternalEvidence($methods, str_repeat('c', $room), $now);
        $record   = $this->sessions()->signInExternally($this->linkedResult($this->seedIdentity(), evidence: $evidence))->session?->record;

        self::assertNotNull($record);
        self::assertEquals([$evidence], SessionProofs::acceptedEvidence($record));
        self::assertEquals($evidence, SessionProofs::provenance($record)?->evidence);
    }

    /**
     * A session started otherwise has no provenance to read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionNoProviderEstablishedHasNoProvenance(): void
    {
        $session = $this->sessions()->signIn('password', self::credentials($this->seedIdentity()->email))->session;

        self::assertNotNull($session);
        self::assertNull(SessionProofs::provenance($session->record));
    }

    /**
     * Define the guards the tests sign in through.
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
}
