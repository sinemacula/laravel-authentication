<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ChoosesPrincipals;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Integration tests of what a principal choice and a switch of principal do
 * only once their writes commit, inside a caller's transaction, with the
 * attempt counters on a connection of their own, as the rate limit
 * documentation advises for callers who may roll back: `PrincipalSwitched` and
 * `PrincipalChoiceRequired` are reported only on commit, and a choice gives its
 * attempt slots back only once its use of the choice commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversTrait(ChoosesPrincipals::class)]
final class TransactionalChoosesPrincipalsTest extends TestCase
{
    use InteractsWithRateLimits, InteractsWithSessions;

    /** @var string Connection the attempt counters live on. */
    private const string COUNTERS = 'counters';

    /** @var string Guard over `ChoosingMember`, which has no default principal. */
    private const string CHOOSERS = 'choosers';

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string MEMBERS = 'members';

    /** @var string Email of the member that chooses. */
    private const string CHOOSER = 'chooser@example.test';

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
     * Drop the tables and release the clocks.
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
     * A switch inside a caller's transaction reports `PrincipalSwitched` when
     * the transaction commits, not before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsReportedWhenItsTransactionCommits(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signInMember();

        $this->recordEvents([PrincipalSwitched::class]);

        DB::transaction(function () use ($session, $second): void {

            self::assertTrue($this->sessions(self::MEMBERS)->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());
            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(Device::query()->sole()->getAttribute('principal_id')));
    }

    /**
     * A switch rolled back by its caller reports nothing and leaves the device
     * acting as it did, so its refresh token switches it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackSwitchReportsNothing(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signInMember();
        $before  = Device::query()->sole()->getAttributes();

        $this->recordEvents([PrincipalSwitched::class]);

        DB::beginTransaction();

        self::assertTrue($this->sessions(self::MEMBERS)->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame($before, Device::query()->sole()->getAttributes());
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($before['principal_id']));

        self::assertTrue($this->sessions(self::MEMBERS)->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
    }

    /**
     * A sign-in that offers a choice inside a caller's transaction reports
     * `PrincipalChoiceRequired` when the transaction commits, and nothing when
     * it is rolled back, which leaves no choice to make.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsReportedOnlyOnceItsTransactionCommits(): void
    {
        $this->seedChooser();

        $this->recordEvents([PrincipalChoiceRequired::class]);

        DB::beginTransaction();

        $rolledBack = $this->offer();

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertNull($this->sessions(self::CHOOSERS)->choice($rolledBack));

        DB::transaction(function (): void {

            $this->offer();

            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([PrincipalChoiceRequired::class], $this->recordedClasses());
    }

    /**
     * A choice made inside a transaction its caller rolls back gives no slot
     * back and leaves the choice to be made again; made again, it gives each
     * slot back once, so the failed attempt before it stays counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackChoiceGivesNoSlotBack(): void
    {
        [$member, $first] = $this->seedChooser();

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions(self::CHOOSERS)->signIn('password', ['email' => self::CHOOSER, 'password' => 'wrong'])->reason);

        $token = $this->offer();

        self::assertSame([2, 2, 2], $this->hits($member));

        DB::beginTransaction();

        self::assertTrue($this->sessions(self::CHOOSERS)->choose($token, $first)->isSignedIn());

        DB::rollBack();

        self::assertSame([2, 2, 2], $this->hits($member));
        self::assertSame(1, PendingSignIn::query()->count());
        self::assertSame(0, Device::query()->count());

        DB::transaction(function () use ($token, $first, $member): void {

            self::assertTrue($this->sessions(self::CHOOSERS)->choose($token, $first)->isSignedIn());
            self::assertSame([2, 2, 2], $this->hits($member));
        });

        self::assertSame([1, 1, 1], $this->hits($member));
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame(1, Device::query()->count());
    }

    /**
     * Configure the guards, a guard over the choosing members, and the counters
     * on a second connection to the test database (a database of its own on
     * SQLite, where each in-memory connection has one).
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

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
        $config->set('database.connections.' . self::COUNTERS, $config->array('database.connections.testing'));
        $config->set('authentication.rate_limits.connection', self::COUNTERS);
    }

    /**
     * Persist a member with its default membership and a second one, each in
     * its own active tenant.
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMembership, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     */
    private function seedMemberships(): array
    {
        [$member, $first] = $this->seedMember();

        $other = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        return [$first, ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()])];
    }

    /**
     * Sign the member in as its default membership.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signInMember(): SignedInSession
    {
        $session = $this->sessions(self::MEMBERS)->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Persist a member with two memberships, each in its own active tenant.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member      = ChoosingMember::query()->create(['email' => self::CHOOSER, 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant        = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);
            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$member, $memberships[0]];
    }

    /**
     * Sign the chooser in by password and return the choice token it is
     * offered.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function offer(): string
    {
        $choice = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials(self::CHOOSER))->choice;

        self::assertNotNull($choice);

        return $choice->token;
    }

    /**
     * The hits on the chooser's identifier, the client IP address's and the
     * account's sign-in counters, read on the counters' connection.
     *
     * @param  \Tests\Integration\Fixtures\ChoosingMember  $member
     * @return list<int>
     */
    private function hits(ChoosingMember $member): array
    {
        $keys = [
            self::counterKey(self::CHOOSERS, 'sign_in', 'per_identifier', self::CHOOSER),
            self::counterKey(self::CHOOSERS, 'sign_in', 'per_ip', self::CLIENT_IP),
            self::counterKey('sign_in', 'per_account', AccountAttempts::account($member)),
        ];

        return array_map(static function (string $key): int {
            $hits = DB::connection(self::COUNTERS)->table('rate_limits')->where('key', $key)->value('hits');

            return is_numeric($hits) ? (int) $hits : 0;
        }, $keys);
    }
}
