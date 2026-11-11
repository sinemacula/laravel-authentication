<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests for bulk and single revocations against real rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(RevocationWriter::class)]
final class RevocationWriterTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * More sessions than one chunk are all revoked and each reported once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokesPastOneChunk(): void
    {
        $identity = $this->seedIdentity();
        $count    = RevocationWriter::CHUNK * 2 + 1;

        foreach (array_chunk(range(1, $count), 200) as $chunk) {
            DB::table('authentication_sessions')->insert(array_map(fn (int $index): array => $this->sessionRow($identity, $index), $chunk));
        }

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame($count, $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertSame(0, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertCount($count + 1, $this->recorded);
        self::assertInstanceOf(SignedOutEverywhere::class, end($this->recorded));
        $sessions = array_map(static fn (object $event): ?string => $event instanceof SessionRevoked ? $event->context->sessionId : null, array_slice($this->recorded, 0, $count));

        self::assertCount($count, array_unique($sessions));
    }

    /**
     * Sessions already revoked are skipped and keep their first revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSkipsSessionsAlreadyRevoked(): void
    {
        $identity = $this->seedIdentity();
        $revoked  = ['revoked_at' => '2027-01-15 09:00:00', 'revoked_reason' => 'signed_out'];

        DB::table('authentication_sessions')->insert($this->sessionRow($identity, 1));
        DB::table('authentication_sessions')->insert($revoked + $this->sessionRow($identity, 2));

        $updates = 0;

        DB::listen(static function (QueryExecuted $query) use (&$updates): void {
            $updates += str_starts_with(strtolower($query->sql), 'update') ? 1 : 0;
        });

        self::assertSame(1, $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertSame(1, $updates);
        self::assertSame('signed_out', DB::table('authentication_sessions')->where('client_name', 'client-2')->value('revoked_reason'));
    }

    /**
     * Revocations are reported only once the transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsOnlyOnceTheRevocationCommits(): void
    {
        $identity = $this->seedIdentity();

        DB::table('authentication_sessions')->insert([$this->sessionRow($identity, 1), $this->sessionRow($identity, 2)]);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        try {
            DB::transaction(function () use ($identity): never {

                $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED);

                self::assertSame([], $this->recorded);

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            self::assertSame([], $this->recorded);
        }

        self::assertSame(2, DB::table('authentication_sessions')->whereNull('revoked_at')->count());

        DB::transaction(function () use ($identity): void {

            $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED);

            self::assertSame([], $this->recorded);
        });

        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
    }

    /**
     * A session another writer revoked meanwhile is not revoked again or
     * reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRevokedMeanwhileIsNotReported(): void
    {
        $identity = $this->seedIdentity();

        DB::table('authentication_sessions')->insert([$this->sessionRow($identity, 1), $this->sessionRow($identity, 2)]);

        $first = DB::table('authentication_sessions')->orderBy('id')->value('id');
        $raced = false;

        DB::listen(static function (QueryExecuted $query) use (&$raced, $first): void {

            if ($raced || !str_starts_with(strtolower($query->sql), 'select')) {
                return;
            }

            $raced = true;

            DB::table('authentication_sessions')->where('id', $first)->update(['revoked_at' => '2027-01-15 09:00:00', 'revoked_reason' => 'rotation_reuse']);
        });

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertCount(1, array_filter($this->recorded, static fn (object $event): bool => $event instanceof SessionRevoked));
        self::assertSame('rotation_reuse', DB::table('authentication_sessions')->where('id', $first)->value('revoked_reason'));
        self::assertSame('revoked', DB::table('authentication_sessions')->where('id', '!=', $first)->value('revoked_reason'));
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
    }

    /**
     * A single revocation of a session revoked meanwhile changes and reports
     * nothing.
     *
     * @return void
     */
    public function testASingleRevocationOfASessionRevokedMeanwhileReportsNothing(): void
    {
        $identity = $this->seedIdentity();

        DB::table('authentication_sessions')->insert($this->sessionRow($identity, 1));

        $session = Session::query()->firstOrFail();

        DB::table('authentication_sessions')->update(['revoked_at' => '2027-01-15 09:00:00', 'revoked_reason' => 'signed_out']);

        $revocations = new RevocationWriter(app('db'), static fn (): mixed => app('db.transactions'));
        $reported    = false;

        self::assertFalse($revocations->revoke($session, RevocationReason::REVOKED, CarbonImmutable::now(), static function () use (&$reported): void {
            $reported = true;
        }));
        self::assertFalse($reported);
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertNull($session->getRevokedAt());
    }

    /**
     * A failed session transaction leaves the cutoff moved, and a retry
     * finishes the job.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedSessionTransactionLeavesTheCutoffMoved(): void
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'ada@example.test'])->save();
        $identity = CutoffIdentity::query()->findOrFail($identity->id);

        DB::table('authentication_sessions')->insert($this->sessionRow($identity, 1));

        $failing = new \ArrayObject(['on' => true]);

        DB::connection()->beforeExecuting(static function (string $query) use ($failing): void {
            if ($failing['on'] === true && str_starts_with($query, 'update') && str_contains($query, 'authentication_sessions')) {
                throw new \RuntimeException('The session transaction failed.');
            }
        });

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        try {
            $this->sessions()->revokeSessions($identity, RevocationReason::PASSWORD_RESET);
            self::fail('The session transaction did not fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The session transaction failed.', $exception->getMessage());
            self::assertSame(self::NOW, DB::table('cutoff_identities')->value('tokens_valid_after'));
            self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
            self::assertSame([], $this->recorded);
        } finally {
            $failing['on'] = false;
        }

        self::assertSame(1, $this->sessions()->revokeSessions($identity, RevocationReason::PASSWORD_RESET));
        self::assertNull($this->recordedEvent(SignedOutEverywhere::class)->tokensValidAfter);
    }

    /**
     * Register the session guards.
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
     * A live session of the identity.
     *
     * @param  \Tests\Integration\Fixtures\CutoffIdentity|\Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  int  $index
     * @return array<string, mixed>
     */
    private function sessionRow(CutoffIdentity|IntegrationIdentity $identity, int $index): array
    {
        return [
            'id'                   => (string) Str::uuid7(),
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $identity::class,
            'authenticatable_id'   => (string) $identity->id,
            'principal_type'       => $identity::class,
            'principal_id'         => (string) $identity->id,
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'client_name'          => 'client-' . $index,
            'refresh_key'          => hash('sha256', 'refresh-' . $index),
            'signed_in_at'         => '2027-01-15 09:00:00',
            'idle_expires_at'      => '2027-02-15 09:00:00',
            'absolute_expires_at'  => '2027-07-15 09:00:00',
        ];
    }
}
