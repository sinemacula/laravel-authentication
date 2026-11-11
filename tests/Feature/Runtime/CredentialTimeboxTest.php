<?php

declare(strict_types = 1);

namespace Tests\Feature\Runtime;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Fixtures\Passwords\RecordingTimebox;
use Tests\TestCase;

/**
 * Feature tests of the credential timebox of one guard instance, which every
 * later failed check on the guard waits out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(CredentialTimebox::class)]
final class CredentialTimeboxTest extends TestCase
{
    use InteractsWithPasswords;

    /** @var int The credential timebox budget, in microseconds. */
    private const int BUDGET = 400000;

    /** @var \Tests\Fixtures\Passwords\RecordingTimebox The guard's timebox. */
    private RecordingTimebox $box;

    /**
     * Create the tables, seed an identity, and give the guards a timebox that
     * records its waits instead of sleeping.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createPasswordTables();
        self::seedPasswordIdentity();

        $this->box = new RecordingTimebox;

        app()->instance(Timebox::class, $this->box);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();

        parent::tearDown();
    }

    /**
     * A failed `validate()` after a successful one on the same guard waits out
     * the box.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedValidationAfterASuccessfulOneWaits(): void
    {
        $guard = $this->freshGuard('web');

        self::assertTrue($guard->validate(self::credentials()));
        self::assertFalse($guard->validate(['email' => 'ada@example.test', 'password' => 'not the password']));

        self::assertSame([true, false], $this->box->endedEarly);
        self::assertCount(1, $this->box->waits);
        self::assertGreaterThan(0, $this->box->waits[0]);
    }

    /**
     * A failed `attempt()` or `validate()` after a successful `attempt()` on
     * the same guard waits out the box.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedSignInAfterASuccessfulOneWaits(): void
    {
        $guard = $this->freshGuard('web');

        self::assertTrue($guard->attempt(self::credentials()));
        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'not the password']));
        self::assertFalse($guard->validate(['email' => 'nobody@example.test', 'password' => 'not the password']));

        self::assertSame([true, false, false], $this->box->endedEarly);
        self::assertCount(2, $this->box->waits);
    }

    /**
     * A timeboxed check that does not end the box early waits it out after an
     * earlier one ended early.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATimeboxedCheckAfterOneThatEndedEarlyWaits(): void
    {
        $guard = $this->freshGuard('web');

        self::assertSame('reset', $guard->context()->timebox()->run(static fn (Timebox $timebox): string => $timebox->returnEarly() === $timebox ? 'reset' : 'not reset'));
        self::assertSame('invalid', $guard->context()->timebox()->run(static fn (): string => 'invalid'));

        self::assertSame([true, false], $this->box->endedEarly);
        self::assertCount(1, $this->box->waits);
    }

    /**
     * Configure the guards, with a timebox budget large enough to leave a wait
     * after each check.
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

        self::configurePasswordGuards($config);

        $config->set('authentication.timebox.credentials_microseconds', self::BUDGET);
    }
}
