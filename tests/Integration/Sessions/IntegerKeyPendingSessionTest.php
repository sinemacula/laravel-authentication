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
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegerKeySession;
use Tests\TestCase;

/**
 * Integration tests of a pending session whose key the database issues as an
 * integer, against each supported database: its credential is
 * `<integer>.<secret>`, it names the session, and it is satisfied in place,
 * while a credential whose key is no integer names nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessions::class)]
#[CoversClass(SessionWriter::class)]
final class IntegerKeyPendingSessionTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The integer-keyed session table the tests sign in to. */
    private const string TABLE = 'integer_key_sessions';

    /**
     * Freeze the clocks, create the tables, point the session model and its
     * table at the integer-keyed ones, and ask every sign-in for a further
     * factor.
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

        self::createSessionRecordTable(self::TABLE, incrementing: true);

        config()->set('authentication.session.model', IntegerKeySession::class);
        config()->set('authentication.session.table', self::TABLE);

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
     * The pending credential of an integer-keyed session carries the integer
     * key before its secret, names the session, and is satisfied in place: the
     * same row activates, keeping its key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIntegerKeyedPendingSessionIsNamedAndSatisfiedByItsCredential(): void
    {
        $identity = $this->seedIdentity();

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $key = IdentifierCoercion::stringify(DB::table(self::TABLE)->value('id'));

        self::assertNotNull($key);
        self::assertMatchesRegularExpression('/^\d+$/', $key);
        self::assertStringStartsWith($key . '.', $result->credential->reveal());
        self::assertSame($key, IdentifierCoercion::stringify($this->sessions()->pending($result->credential->reveal())?->id));

        $satisfied = $this->sessions()->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN));

        self::assertTrue($satisfied->isSignedIn());
        self::assertSame($key, IdentifierCoercion::stringify($satisfied->session?->record->getKey()));
        self::assertSame(1, DB::table(self::TABLE)->count());
        self::assertSame('active', DB::table(self::TABLE)->value('status'));
    }

    /**
     * A credential whose key is no integer names no integer-keyed session, and
     * fails as `pending_invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialWhoseKeyIsNoIntegerNamesNothing(): void
    {
        $identity = $this->seedIdentity();

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($result->credential);

        [, $secret] = explode('.', $result->credential->reveal(), 2);

        self::assertNull($this->sessions()->pending('not-a-number.' . $secret));
        $proof = self::adapterProof($identity, 'api', $result->pending?->id, Purpose::SIGN_IN);

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy('not-a-number.' . $secret, $proof)->reason);
        self::assertSame('pending', DB::table(self::TABLE)->value('status'));
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
}
