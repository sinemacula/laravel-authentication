<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;

/**
 * Unit tests for the breached-password checker fake tests bind in place of the
 * application's checker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeBreachedPasswordChecker::class)]
final class FakeBreachedPasswordCheckerTest extends TestCase
{
    /**
     * Restore the global container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * `fake()` binds a fresh instance as the checker in the container given, or
     * in the global container when none is, and returns it.
     *
     * @return void
     */
    public function testFakeBindsAFreshInstanceAsTheChecker(): void
    {
        $given = new Container;
        $fake  = FakeBreachedPasswordChecker::fake(container: $given);

        self::assertSame($fake, $given->make(BreachedPasswordChecker::class));

        $global = new Container;

        Container::setInstance($global);

        $other = FakeBreachedPasswordChecker::fake();

        self::assertSame($other, $global->make(BreachedPasswordChecker::class));
        self::assertNotSame($fake, $other);
        self::assertSame($fake, $given->make(BreachedPasswordChecker::class));
    }

    /**
     * Exactly the passwords given are breached, compared byte for byte, and
     * every password asked about is kept, oldest first, and can be filtered,
     * counted and forgotten.
     *
     * @return void
     */
    public function testFindsTheGivenPasswordsAndKeepsEveryOneAsked(): void
    {
        $fake = FakeBreachedPasswordChecker::fake(['password123'], new Container);

        self::assertSame([], $fake->checked());
        self::assertFalse($fake->hasChecked());

        self::assertTrue($fake->isBreached('password123'));
        self::assertFalse($fake->isBreached('Password123'));
        self::assertFalse($fake->isBreached('password123 '));

        $padded = static fn (string $password): bool => str_ends_with($password, ' ');
        $none   = static fn (string $password): bool => $password === 'never asked';

        self::assertSame(['password123', 'Password123', 'password123 '], $fake->checked());
        self::assertSame(['password123 '], $fake->checked($padded));
        self::assertTrue($fake->hasChecked());
        self::assertTrue($fake->hasChecked($padded));
        self::assertFalse($fake->hasChecked($none));
        self::assertSame(3, $fake->count());

        $fake->forget();

        self::assertSame([], $fake->checked());
        self::assertSame(0, $fake->count());
    }

    /**
     * While unavailable the fake throws as a service that is down would, with
     * no password in the message, and still keeps the password asked; it can be
     * made available again.
     *
     * @return void
     */
    public function testAnUnavailableFakeCannotAnswer(): void
    {
        $fake = FakeBreachedPasswordChecker::fake(['password123'], new Container);

        self::assertSame($fake, $fake->unavailable());

        try {
            $fake->isBreached('password123');
            self::fail('An unavailable checker answered.');
        } catch (BreachedPasswordCheckUnavailableException $exception) {
            self::assertSame('The breached-password service is unavailable.', $exception->getMessage());
        }

        self::assertSame(['password123'], $fake->checked());
        self::assertTrue($fake->unavailable(false)->isBreached('password123'));
    }
}
