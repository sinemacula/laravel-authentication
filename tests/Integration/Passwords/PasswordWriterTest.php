<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use Tests\Concerns\InteractsWithPasswords;
use Tests\TestCase;

/**
 * Integration tests of setting a password inside a transaction the caller
 * holds, on the engine the suite runs on: the hash, the cutoff and the
 * revocations are part of it, and every report waits for its commit, so a
 * rollback leaves the password, the sessions and the listeners untouched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordWriter::class)]
final class PasswordWriterTest extends TestCase
{
    use InteractsWithPasswords;

    /** @var string The frozen time every write happens at. */
    private const string NOW = '2026-10-29 09:30:00';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeClock(CarbonImmutable::parse(self::NOW));
        self::createPasswordTables();
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();
        self::freezeClock(null);

        parent::tearDown();
    }

    /**
     * A reset inside a transaction the caller rolls back leaves the old
     * password, every device live and the cutoff unset, and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRollbackUndoesTheWholeReset(): void
    {
        $identity = self::seedPasswordIdentity();

        $this->signInWithPassword('web');
        $this->signInWithPassword('admin');
        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        DB::beginTransaction();

        self::assertSame(2, Auth::passwords('web')->set($identity, 'a brand new passphrase', PasswordFlow::RESET)->revoked);
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $stored->password));
        self::assertNull($stored->tokens_valid_after);
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Inside a transaction the caller commits, the revocations and then
     * `PasswordSet` are reported only once it commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportsWaitForTheCallersCommit(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword('web')->device;

        $this->signInWithPassword('admin');
        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        DB::transaction(function () use ($identity, $kept): void {
            Auth::passwords('web')->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE, $kept);

            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([DeviceRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());
        self::assertSame(1, DB::table('devices')->whereNull('revoked_at')->count());
    }

    /**
     * A client the caller names is the one `PasswordSet` reports; otherwise the
     * request being served.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientNamedIsReported(): void
    {
        $identity = self::seedPasswordIdentity();
        $client   = new ClientContext('198.51.100.9', 'Kiosk/2.0');
        $context  = $this->freshGuard('web')->context();
        $writer   = new PasswordWriter($context, SessionRevocations::forContext($context, app()), app());

        $this->recordEvents([PasswordSet::class]);

        $writer->write($identity, 'a brand new passphrase', PasswordFlow::CHANGE, null, $client);
        $writer->write($identity, 'another new passphrase', PasswordFlow::CHANGE);

        [$named, $served] = $this->recorded;

        self::assertInstanceOf(PasswordSet::class, $named);
        self::assertInstanceOf(PasswordSet::class, $served);
        self::assertSame($client, $named->context->client);
        self::assertSame(self::CLIENT_IP, $served->context->client->ip);
    }

    /**
     * `PasswordSet` goes to the dispatcher the guard had when the password was
     * written, while the revocations' reports go to the one it has when the
     * caller commits: a dispatcher swapped in between receives the revocations
     * only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePasswordSetKeepsTheDispatcherOfTheWriteAndTheRevocationsTakeTheOneAtTheCommit(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword('web')->device;

        $this->signInWithPassword('admin');

        $guard    = $this->freshGuard('web');
        $swapped  = new Dispatcher(app());
        $received = [];

        foreach ([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class] as $class) {
            $swapped->listen($class, static function (object $event) use (&$received): void {
                $received[] = $event::class;
            });
        }

        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        DB::transaction(static function () use ($identity, $kept, $guard, $swapped): void {
            self::assertSame(1, Auth::passwords('web')->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE, $kept)->revoked);

            $guard->setDispatcher($swapped);
        });

        self::assertSame([PasswordSet::class], $this->recordedClasses());
        self::assertSame([DeviceRevoked::class, SignedOutEverywhere::class], $received);
    }

    /**
     * Configure the guards.
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

        self::configurePasswordGuards($app->make(ConfigRepository::class));
    }
}
