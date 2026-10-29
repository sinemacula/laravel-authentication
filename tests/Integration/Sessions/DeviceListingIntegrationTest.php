<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ScopesActiveDevices;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;
use SineMacula\Laravel\Authentication\Sessions\DeviceSummary;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests for which devices are active and how an identity's device
 * list is ordered and paged, against real rows on each supported database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveDevices::class)]
#[CoversTrait(ScopesActiveDevices::class)]
final class DeviceListingIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The frozen time every test lists at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clock and create the identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse(self::NOW));
        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A device is active while it is unrevoked and before both deadlines: a
     * deadline that names the current second has passed. The scope and the
     * listing agree, and the listing holds only the identity's devices, of
     * every guard.
     *
     * @return void
     */
    public function testActiveMeansUnrevokedAndBeforeBothDeadlines(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $now      = Carbon::parse(self::NOW);

        $this->insertDevice($identity, '01', revoked: true);
        $this->insertDevice($identity, '02', idle: $now);
        $this->insertDevice($identity, '03', idle: $now->copy()->addSecond());
        $this->insertDevice($identity, '04', absolute: $now);
        $this->insertDevice($identity, '05', absolute: $now->copy()->addSecond());
        $this->insertDevice($identity, '06', guard: 'admin');
        $this->insertDevice($other, '07');

        self::assertEqualsCanonicalizing([self::key('03'), self::key('05'), self::key('06'), self::key('07')], Device::query()->active()->pluck('id')->all());

        $listed = $this->sessions()->devices($identity, 100);

        self::assertSame(3, $listed->total());
        $ids = array_map(static fn (DeviceSummary $summary): string => $summary->id, $listed->items());

        self::assertEqualsCanonicalizing([self::key('03'), self::key('05'), self::key('06')], $ids);
    }

    /**
     * The list is ordered by last use, most recent first and never used last,
     * then by key, newest first, so pages are stable on every database.
     *
     * @return void
     */
    public function testOrdersByLastUseThenKeyWithNeverUsedLast(): void
    {
        $identity = $this->seedIdentity();
        $now      = Carbon::parse(self::NOW);

        $this->insertDevice($identity, '01', lastUsed: $now->copy()->subHour());
        $this->insertDevice($identity, '02', lastUsed: null);
        $this->insertDevice($identity, '03', lastUsed: $now->copy()->subMinute());
        $this->insertDevice($identity, '04', lastUsed: $now->copy()->subHour());
        $this->insertDevice($identity, '05', lastUsed: null);
        $this->insertDevice($identity, '06', lastUsed: $now->copy()->subDay());

        $sessions = $this->sessions();
        $order    = [];

        foreach ([1, 2, 3] as $page) {

            $listed = $sessions->devices($identity, 2, $page);

            self::assertSame(6, $listed->total());
            self::assertSame(3, $listed->lastPage());

            foreach ($listed->items() as $summary) {
                $order[] = $summary->id;
            }
        }

        self::assertSame([self::key('03'), self::key('04'), self::key('01'), self::key('06'), self::key('05'), self::key('02')], $order);
    }

    /**
     * The summary of a listed device carries what the row records.
     *
     * @return void
     */
    public function testSummarisesTheRow(): void
    {
        $identity = $this->seedIdentity();
        $now      = Carbon::parse(self::NOW);

        $this->insertDevice($identity, '01', lastUsed: $now->copy()->subMinute());

        $summary = $this->sessions()->devices($identity)->items()[0];

        self::assertSame(
            [
                'id'                   => self::key('01'),
                'guard'                => 'api',
                'sign_in_method'       => 'password',
                'client_name'          => 'Client 01',
                'platform'             => 'macOS',
                'created_at'           => '2027-01-14T10:00:00+00:00',
                'created_ip'           => '198.51.100.1',
                'created_user_agent'   => 'Created/1.0',
                'signed_in_at'         => '2027-01-15T08:00:00+00:00',
                'last_used_at'         => '2027-01-15T09:59:00+00:00',
                'last_used_ip'         => '198.51.100.2',
                'last_used_user_agent' => 'Used/1.0',
                'idle_expires_at'      => '2027-02-14T10:00:00+00:00',
                'absolute_expires_at'  => '2027-03-16T10:00:00+00:00',
                'current'              => false,
            ],
            $summary->toArray(),
        );
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
     * The key of the numbered test device: UUIDs that sort in their number's
     * order on every database.
     *
     * @param  string  $number
     * @return string
     */
    private static function key(string $number): string
    {
        return '018f0000-0000-7000-8000-0000000000' . $number;
    }

    /**
     * Insert a device of the identity, live for a month unless told otherwise.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $number
     * @param  bool  $revoked
     * @param  ?\Illuminate\Support\Carbon  $idle
     * @param  ?\Illuminate\Support\Carbon  $absolute
     * @param  string  $guard
     * @param  ?\Illuminate\Support\Carbon  $lastUsed
     * @return void
     */
    private function insertDevice(
        IntegrationIdentity $identity,
        string $number,
        bool $revoked = false,
        ?Carbon $idle = null,
        ?Carbon $absolute = null,
        string $guard = 'api',
        ?Carbon $lastUsed = null,
    ): void {
        $now = Carbon::parse(self::NOW);

        DB::table('devices')->insert([
            'id'                   => self::key($number),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->id,
            'principal_type'       => IntegrationIdentity::class,
            'principal_id'         => (string) $identity->id,
            'guard'                => $guard,
            'sign_in_method'       => 'password',
            'client_name'          => 'Client ' . $number,
            'platform'             => 'macOS',
            'created_ip'           => '198.51.100.1',
            'created_user_agent'   => 'Created/1.0',
            'last_used_at'         => $lastUsed,
            'last_used_ip'         => $lastUsed === null ? null : '198.51.100.2',
            'last_used_user_agent' => $lastUsed === null ? null : 'Used/1.0',
            'refresh_key'          => hash('sha256', 'refresh-' . $number),
            'idle_expires_at'      => $idle     ?? $now->copy()->addDays(30),
            'absolute_expires_at'  => $absolute ?? $now->copy()->addDays(60),
            'revoked_at'           => $revoked ? $now->copy()->subMinute() : null,
            'revoked_reason'       => $revoked ? 'revoked' : null,
            'signed_in_at'         => $now->copy()->subHours(2),
            'created_at'           => $now->copy()->subDay(),
            'updated_at'           => $now->copy()->subDay(),
        ]);
    }
}
