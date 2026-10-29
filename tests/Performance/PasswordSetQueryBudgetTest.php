<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Hashing\BcryptHasher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\PasswordPolicy;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use Tests\Concerns\InteractsWithPasswords;

/**
 * Query-budget contracts for setting a password: checking one touches no
 * database; a registration of a stored identity is the one `UPDATE` of its
 * password; a change or a reset adds the bulk revocation (the cutoff's
 * `UPDATE`, one read of the devices, one `UPDATE` per device revoked and the
 * `DELETE` of the pending sign-ins); and a rejected password writes nothing.
 * The hasher runs once per password set, never for one rejected.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordService::class)]
#[CoversClass(PasswordWriter::class)]
#[CoversClass(PasswordPolicy::class)]
final class PasswordSetQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithPasswords;

    /** @var int How many hashes were made. */
    private int $hashes = 0;

    /**
     * Create the tables and count the hashes made.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now));

        self::createPasswordTables();

        $bcrypt = new BcryptHasher(['rounds' => 4]);
        $hasher = \Mockery::mock(Hasher::class);

        $hasher->shouldReceive('make')->andReturnUsing(function (string $value) use ($bcrypt): string {
            $this->hashes++;

            return $bcrypt->make($value);
        });
        $hasher->shouldReceive('check')->andReturnUsing(static fn (string $value, mixed $hash): bool => $bcrypt->check($value, $hash));
        $hasher->shouldReceive('needsRehash')->andReturn(false);

        app()->instance(Hasher::class, $hasher);
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Checking a password, and rejecting one, cost no query and no hash.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCheckingAndRejectingTouchNoDatabase(): void
    {
        $identity = self::seedPasswordIdentity();
        $service  = $this->service();

        $this->hashes = 0;

        $this->assertQueryBudget(0, 0, static function () use ($service, $identity): void {
            $service->check('a long enough passphrase');
            $service->set($identity, 'short', PasswordFlow::CHANGE);
        });

        self::assertSame(0, $this->hashesMade());
    }

    /**
     * A registration of a stored identity is one `UPDATE` and one hash.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationOfAStoredIdentityIsOneUpdate(): void
    {
        $identity = self::seedPasswordIdentity();
        $service  = $this->service();

        $this->hashes = 0;

        $this->assertQueryBudget(0, 1, static fn () => $service->set($identity, 'a brand new passphrase', PasswordFlow::REGISTRATION));

        self::assertSame(1, $this->hashesMade());
    }

    /**
     * A change that keeps one of three devices is the password's `UPDATE`, the
     * cutoff's `UPDATE`, one read of the devices, one `UPDATE` for each of the
     * two it revokes and the `DELETE` of the pending sign-ins.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeIsTheUpdateAndTheBulkRevocation(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword('web')->device;

        $this->signInWithPassword('web');
        $this->signInWithPassword('admin');

        $service = $this->service();

        $this->hashes = 0;

        $result = $this->assertQueryBudget(1, 5, static fn () => $service->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE, $kept));

        self::assertSame(2, $result->revoked);
        self::assertSame(1, $this->hashesMade());
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

    /**
     * How many hashes were made since the count was last reset.
     *
     * @return int
     */
    private function hashesMade(): int
    {
        return $this->hashes;
    }

    /**
     * The `web` guard's password service, on a guard resolved for a fresh
     * request.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     */
    private function service(): PasswordService
    {
        $this->freshGuard('web');

        return Auth::passwords('web');
    }
}
