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
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
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
 * holds.
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
     * A reset the caller rolls back leaves the password and sessions untouched
     * and reports nothing.
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
        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::beginTransaction();

        self::assertSame(2, Auth::passwords('web')->set($identity, 'a brand new passphrase', PasswordFlow::RESET, self::requestClient())->revoked);
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $stored->password));
        self::assertNull($stored->tokens_valid_after);
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * The revocations and `PasswordSet` are reported only once the caller
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportsWaitForTheCallersCommit(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword('web')->record;

        $this->signInWithPassword('admin');
        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::transaction(function () use ($identity, $kept): void {
            Auth::passwords('web')->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE, self::requestClient(), $kept);

            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());
        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
    }

    /**
     * Every report of a write carries the client it was given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientGivenIsReported(): void
    {
        $identity = self::seedPasswordIdentity();

        $this->signInWithPassword('web');
        $this->signInWithPassword('admin');

        $client  = new ClientContext('198.51.100.9', 'Kiosk/2.0');
        $context = $this->freshGuard('web')->context();
        $writer  = new PasswordWriter($context, SessionRevocations::forContext($context, app()), app());

        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(2, $writer->write($identity, 'a brand new passphrase', PasswordFlow::RESET, $client));
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());
        self::assertSame([$client, $client, $client, $client], array_map(
            static fn (PasswordSet|SessionRevoked|SignedOutEverywhere $event): ClientContext => $event->context->client,
            $this->recordedAs(PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class),
        ));
        self::assertSame(self::CLIENT_IP, $context->client()->ip);
    }

    /**
     * The reports go to the dispatcher the guard has when the caller commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePasswordSetAndTheRevocationsReachTheDispatcherBoundAtTheCommit(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword('web')->record;

        $this->signInWithPassword('admin');

        $guard    = $this->freshGuard('web');
        $swapped  = new Dispatcher(app());
        $received = [];

        foreach ([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class] as $class) {
            $swapped->listen($class, static function (object $event) use (&$received): void {
                $received[] = $event::class;
            });
        }

        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::transaction(static function () use ($identity, $kept, $guard, $swapped): void {
            self::assertSame(1, Auth::passwords('web')->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE, self::requestClient(), $kept)->revoked);

            $guard->setDispatcher($swapped);
        });

        self::assertSame([], $this->recordedClasses());
        self::assertSame([SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $received);
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
