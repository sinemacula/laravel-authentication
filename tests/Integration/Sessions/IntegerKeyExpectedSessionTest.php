<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegerKeySession;
use Tests\TestCase;

/**
 * Integration tests of the expected session a refresh, a switch and a sign-out
 * by refresh credential take, against each supported database, for a session
 * the database keys by an integer: the integer and its string form are the
 * session, a number written otherwise is not, and a token proving another
 * session is refused as `session_mismatch`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRefresh::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversClass(SessionSignOut::class)]
final class IntegerKeyExpectedSessionTest extends TestCase
{
    use InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The integer-keyed session table the tests sign in to. */
    private const string TABLE = 'integer_key_sessions';

    /**
     * Freeze the clocks, create the tables and point the session model and its
     * table at the integer-keyed ones.
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
     * A refresh expecting the integer key of its session, or the string form of
     * it, rotates the session; a number written with a leading zero, or the key
     * of another session, is refused as `session_mismatch`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshComparesTheIntegerKeyAsAString(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $other   = $this->signedIn();
        $key     = self::keyOf($session);

        $refresh = fn (SignedInSession $from, int|string $expected) => $this->sessions()->refresh(
            PresentedRefreshToken::fromBody((string) $from->tokens->refreshToken?->reveal()),
            self::requestClient(),
            $expected,
        );

        self::assertSame(FailureReason::SESSION_MISMATCH, $refresh($session, '0' . $key)->reason);
        self::assertSame(FailureReason::SESSION_MISMATCH, $refresh($session, self::keyOf($other))->reason);

        $integer = $refresh($session, $key);

        self::assertTrue($integer->isRefreshed());

        $string = $refresh($other, (string) self::keyOf($other));

        self::assertTrue($string->isRefreshed());
    }

    /**
     * A sign-out expecting the integer key of its session, or the string form
     * of it, signs it out; one expecting another is refused and revokes
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignOutComparesTheIntegerKeyAsAString(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $other   = $this->signedIn();

        $signOut = fn (SignedInSession $from, int|string $expected) => $this->sessions()->signOutWith(
            PresentedRefreshToken::fromBody((string) $from->tokens->refreshToken?->reveal()),
            self::requestClient(),
            $expected,
        );

        self::assertSame(FailureReason::SESSION_MISMATCH, $signOut($session, '0' . self::keyOf($session))->reason);
        self::assertSame(FailureReason::SESSION_MISMATCH, $signOut($session, self::keyOf($other))->reason);
        self::assertNull(IntegerKeySession::query()->whereKey(self::keyOf($session))->value('revoked_at'));
        self::assertTrue($signOut($session, self::keyOf($session))->isSignedOut());
        self::assertTrue($signOut($other, (string) self::keyOf($other))->isSignedOut());
    }

    /**
     * A switch expecting the integer key of its session, or the string form of
     * it, is made; one expecting another is refused as `session_mismatch`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchComparesTheIntegerKeyAsAString(): void
    {
        [$member] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $session = $this->members($member);
        $another = $this->members($member);

        $switch = fn (SignedInSession $from, ActivatableTenantMembership $to, int|string $expected) => $this->sessions('members')->switchTo(
            PresentedRefreshToken::fromBody((string) $from->tokens->refreshToken?->reveal()),
            SwitchTarget::principal($to),
            self::requestClient(),
            $expected,
        );

        self::assertSame(FailureReason::SESSION_MISMATCH, $switch($session, $second, '0' . self::keyOf($session))->reason);
        self::assertSame(FailureReason::SESSION_MISMATCH, $switch($session, $second, self::keyOf($another))->reason);

        $integer = $switch($session, $second, self::keyOf($session));

        self::assertTrue($integer->isSwitched());
        self::assertTrue($switch($another, $second, (string) self::keyOf($another))->isSwitched());
    }

    /**
     * Register the session guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The integer key of the signed-in session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return int
     */
    private static function keyOf(SignedInSession $session): int
    {
        $key = $session->record->getKey();

        self::assertIsInt($key);

        return $key;
    }

    /**
     * Sign the identity in on the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Sign the member in on the `members` guard as its default membership.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function members(ActivatableTenantMember $member): SignedInSession
    {
        $context = SignInContext::fromRequest(request(), principal: $member->resolveDefaultPrincipal());
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        return $session;
    }
}
