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
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\DottedKeySession;
use Tests\TestCase;

/**
 * Integration tests of a pending session whose key holds a `.`, against each
 * supported database: its credential is `<key>.<secret>`, split at its last
 * `.`, so it names the session, is satisfied in place, and is discarded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessions::class)]
final class DottedKeyPendingSessionTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The string-keyed session table the tests sign in to. */
    private const string TABLE = 'dotted_key_sessions';

    /**
     * Freeze the clocks, create the tables, point the session model and its
     * table at the dotted-key ones, and ask every sign-in for a further factor.
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

        self::createSessionRecordTable(self::TABLE, stringKey: true);

        config()->set('authentication.session.model', DottedKeySession::class);
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
     * The pending credential of a session whose key holds a `.` carries the
     * whole key before its secret, names the session for an action, and is
     * satisfied in place: the same row activates, keeping its key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADottedKeyPendingSessionIsNamedAndSatisfiedByItsCredential(): void
    {
        $identity = $this->seedIdentity();

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $key = IdentifierCoercion::stringify(DB::table(self::TABLE)->value('id'));

        self::assertNotNull($key);
        self::assertStringStartsWith('session.', $key);
        self::assertStringStartsWith($key . '.', $result->credential->reveal());
        self::assertSame($key, IdentifierCoercion::stringify($this->sessions()->pending($result->credential->reveal(), PendingAction::SEND_CODE)?->id));

        $satisfied = $this->sessions()->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN));

        self::assertTrue($satisfied->isSignedIn());
        self::assertSame($key, IdentifierCoercion::stringify($satisfied->session?->record->getKey()));
        self::assertSame('active', DB::table(self::TABLE)->value('status'));
    }

    /**
     * A pending session whose key holds a `.` is discarded through its
     * credential.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADottedKeyPendingSessionIsDiscardedByItsCredential(): void
    {
        $this->seedIdentity();

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($result->credential);
        self::assertTrue($this->sessions()->discard($result->credential->reveal()));
        self::assertNotNull(DB::table(self::TABLE)->value('revoked_at'));
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
