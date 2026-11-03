<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegerKeySession;
use Tests\TestCase;

/**
 * Integration tests of a session key the database issues again, against each
 * supported database: an integer-keyed session table truncated without its
 * proofs and provenance restarts its counter, and the next sign-in of the same
 * identity on the same guard gets the key an earlier session held. The new
 * session counts only its own sign-in's proofs, so the earlier session's
 * step-up neither appears in its `amr` nor makes it fresh, and the rows the
 * earlier session left are gone once the sign-in is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionWriter::class)]
#[CoversClass(ProofWriter::class)]
final class ReusedSessionKeyTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The integer-keyed session table the tests sign in to. */
    private const string TABLE = 'integer_key_sessions';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and point the session model and its
     * table at the integer-keyed ones, once the shipped tables are migrated.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->clockAt($this->now);
        $this->createSessionTables();

        self::createSessionRecordTable(self::TABLE, incrementing: true);

        config()->set('authentication.session.model', IntegerKeySession::class);
        config()->set('authentication.session.table', self::TABLE);
    }

    /**
     * Drop the tables, put the session table back for the migrations' rollback
     * and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('authentication.session.table', 'authentication_sessions');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A sign-in whose session gets the key an earlier session of the same
     * identity and guard held, after the sessions were truncated without their
     * proofs, counts only its own first factor: its token's `amr` is its
     * password's alone and its `auth_time` its own sign-in's, a requirement
     * that takes only a step-up finds nothing, and the earlier session's first
     * factor, step-up and provenance are deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWhoseKeyIsIssuedAgainCountsOnlyItsOwnProofs(): void
    {
        $identity = $this->seedIdentity();
        $earlier  = $this->sessions()->signInExternally($this->linkedResult($identity))->session;

        self::assertNotNull($earlier);

        $this->clockAt($this->now->addMinute());

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($identity, 'api', $earlier->record->getKey()))->isIssued());
        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD, 'otp', 'mfa'], AuthenticationClaims::forSession($earlier->record)->methods);

        IntegerKeySession::query()->truncate();

        $signedInAt = $this->now->addMinutes(2);

        $this->clockAt($signedInAt);

        $later = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($later);

        $key    = IdentifierCoercion::stringify($later->record->getKey());
        $claims = Auth::manager()->jwt('api')->parse($later->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertSame(IdentifierCoercion::stringify($earlier->record->getKey()), $key);
        self::assertIsArray($claims);
        self::assertSame([$signedInAt->getTimestamp(), ['pwd']], [$claims['auth_time'] ?? null, $claims['amr'] ?? null]);
        self::assertNull(app(FreshnessPolicy::class)->freshProof($later->record, Operations::FACTOR_CHANGE));
        self::assertSame([['first_factor', 'password']], array_map(static fn (SessionProof $proof): array => [$proof->kind, $proof->method], self::proofsOf($later->record)));
        self::assertSame(0, DB::table('authentication_provenance')->count());
    }

    /**
     * Configure the session guards.
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
     * Move the clocks to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
