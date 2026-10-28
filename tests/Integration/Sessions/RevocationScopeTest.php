<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use Tests\Integration\Fixtures\AccessOnlyCutoffIdentity;
use Tests\Integration\Fixtures\AccessOnlyMember;
use Tests\Integration\Fixtures\CutoffMembership;
use Tests\TestCase;

/**
 * End-to-end tests of revocation in access-only mode, against a database that
 * has none of the package's tables: an identity without `HasDevices`, and a
 * principal owned by one, can hold neither a device nor a pending sign-in, so
 * revoking their sessions only moves their "tokens valid after" cutoff, which
 * is how their device-less tokens end.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevocationScope::class)]
final class RevocationScopeTest extends TestCase
{
    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var list<\SineMacula\Laravel\Authentication\Events\SignedOutEverywhere> The bulk revocations reported. */
    private array $reported = [];

    /**
     * Freeze the clock, create the application's tables only, and record the
     * bulk revocations.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        Schema::create('access_only_cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        Schema::create('access_only_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('cutoff_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        Event::listen(SignedOutEverywhere::class, function (SignedOutEverywhere $event): void {
            $this->reported[] = $event;
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

        foreach (['cutoff_memberships', 'access_only_members', 'access_only_cutoff_identities'] as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();
    }

    /**
     * Every security change of an access-only identity moves its cutoff and
     * reports it, without touching the device or pending sign-in tables, which
     * do not exist.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccessOnlyIdentitysRevocationsOnlyMoveItsCutoff(): void
    {
        self::assertFalse(Schema::hasTable('devices'));
        self::assertFalse(Schema::hasTable('pending_sign_ins'));

        $identity = AccessOnlyCutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => 'unused']);
        $sessions = Auth::sessions('api');

        self::assertSame(0, $sessions->passwordChanged($identity));
        self::assertSame(0, $sessions->passwordReset($identity));
        self::assertSame(0, $sessions->identityDeactivated($identity));
        self::assertSame(0, $sessions->revokeDevices($identity, RevocationReason::REVOKED));

        self::assertSame(self::NOW, $identity->fresh()?->getTokensValidAfter()?->format('Y-m-d H:i:s'));
        self::assertCount(4, $this->reported);
        self::assertSame(self::NOW, $this->reported[0]->tokensValidAfter?->format('Y-m-d H:i:s'));
        self::assertNull($this->reported[1]->tokensValidAfter);
    }

    /**
     * A principal whose owner holds no devices has none to revoke either: its
     * deactivation moves its cutoff, reports its owner, and touches neither of
     * the package's tables.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalOfAnAccessOnlyIdentityOnlyMovesItsCutoff(): void
    {
        $member     = AccessOnlyMember::query()->create(['email' => 'member@example.test', 'password' => 'unused']);
        $membership = CutoffMembership::query()->create(['identity_id' => $member->id]);

        self::assertSame(0, Auth::sessions('api')->principalDeactivated($membership));
        self::assertSame(0, Auth::sessions('api')->revokePrincipalDevices($membership->fresh() ?? $membership, RevocationReason::REVOKED));

        self::assertSame(self::NOW, $membership->fresh()?->getTokensValidAfter()?->format('Y-m-d H:i:s'));
        self::assertCount(2, $this->reported);
        self::assertSame($membership, $this->reported[0]->context->principal);
        self::assertInstanceOf(AccessOnlyMember::class, $this->reported[0]->context->identity);
        self::assertSame((string) $member->id, $this->reported[0]->context->identityId);
    }

    /**
     * Configure an `api` guard over the access-only identities.
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

        $config->set('auth.providers.access_only', ['driver' => 'model', 'model' => AccessOnlyCutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'access_only']);
        $config->set('auth.defaults.guard', 'api');
    }

    /**
     * Run none of the package's migrations: an access-only deployment needs no
     * table of the package.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        // An access-only deployment has none of the package's tables.
    }
}
