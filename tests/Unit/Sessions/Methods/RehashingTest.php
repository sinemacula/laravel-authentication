<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Methods;

use Illuminate\Auth\GenericUser;
use Illuminate\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Hashing\BcryptHasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the mark that tells an automatic password rehash from a change
 * of password.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Rehashing::class)]
final class RehashingTest extends TestCase
{
    /** @var string The password the attempts are made with. */
    private const string PASSWORD = 'secret';

    /** @var \Illuminate\Container\Container|null The container before the test. */
    private ?Container $previous = null;

    /** @var string A hash of the password. */
    private string $hash = '';

    /**
     * Bind the hasher the mark checks a stored hash with.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previous = Container::getInstance();

        $hasher    = new BcryptHasher(['rounds' => 4]);
        $container = new Container;

        $container->instance(Hasher::class, $hasher);

        Container::setInstance($container);

        $this->hash = $hasher->make(self::PASSWORD);
    }

    /**
     * Restore the container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->previous);

        parent::tearDown();
    }

    /**
     * The package's own rehash marks its user, and no other, only while the
     * callback runs, and the callback's result is returned.
     *
     * @return void
     */
    public function testThePackagesRehashMarksItsUserWhileTheCallbackRuns(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 1, 'password' => $this->hash]);

        self::assertFalse($rehashing->isRunningFor($user));

        self::assertSame('rehashed', $rehashing->during($user, static function () use ($rehashing): string {
            self::assertTrue($rehashing->isRunningFor(new GenericUser(['id' => '1', 'password' => 'another hash'])));
            self::assertFalse($rehashing->isRunningFor(new GenericUser(['id' => 2, 'password' => 'another hash'])));
            self::assertFalse($rehashing->isRunningFor(new PlainIdentityFixture(1)));

            return 'rehashed';
        }));

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * A nested rehash does not clear the outer one's mark.
     *
     * @return void
     */
    public function testANestedRehashKeepsTheOuterMark(): void
    {
        $outer     = new GenericUser(['id' => 1, 'password' => $this->hash]);
        $inner     = new GenericUser(['id' => 2, 'password' => $this->hash]);
        $rehashing = new Rehashing;

        $rehashing->during($outer, static function () use ($rehashing, $outer, $inner): void {

            self::assertTrue($rehashing->during($inner, static fn (): bool => $rehashing->isRunningFor($outer) && $rehashing->isRunningFor($inner)));

            self::assertTrue($rehashing->isRunningFor($outer));
            self::assertFalse($rehashing->isRunningFor($inner));
        });

        self::assertFalse($rehashing->isRunningFor($outer));
    }

    /**
     * An exception from the callback propagates and still clears the mark, so a
     * long-running worker never keeps it for later work.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptionClearsTheMark(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 1, 'password' => $this->hash]);

        try {
            $rehashing->during($user, static function (): never {
                throw new \RuntimeException('rehash failed');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('rehash failed', $exception->getMessage());
        }

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * A guard's attempt marks the user it validated, and no other, from the
     * validation until the attempt ends.
     *
     * @return void
     */
    public function testAnAttemptMarksTheUserItValidatedUntilItEnds(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->validated('web', $user);

        self::assertTrue($rehashing->isRunningFor(new GenericUser(['id' => '7', 'password' => $this->hash])));
        self::assertFalse($rehashing->isRunningFor(new GenericUser(['id' => 8, 'password' => $this->hash])));
        self::assertFalse($rehashing->isRunningFor(new PlainIdentityFixture(7, $this->hash)));

        $rehashing->ended('admin');

        self::assertTrue($rehashing->isRunningFor($user));

        $rehashing->ended('web');

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->validated('web', $user);

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * A validation outside an attempt, or by another guard than the one
     * attempting, marks nothing; a new attempt of the guard forgets the user
     * its previous one validated.
     *
     * @return void
     */
    public function testOnlyTheAttemptingGuardsValidationMarks(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        $rehashing->validated('web', $user);

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $user);

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * Inside an attempt, the user is marked only while its stored hash verifies
     * the password the attempt was made with: another password saved before the
     * attempt ends is a change of password.
     *
     * @return void
     */
    public function testAnAttemptMarksItsUserOnlyWhileTheStoredHashVerifiesItsPassword(): void
    {
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD]);
        $rehashing->validated('web', new GenericUser(['id' => 7, 'password' => $this->hash]));

        self::assertFalse($rehashing->isRunningFor(new GenericUser(['id' => 7, 'password' => (new BcryptHasher(['rounds' => 4]))->make('a new password')])));
        self::assertFalse($rehashing->isRunningFor(new GenericUser(['id' => 7, 'password' => null])));
        self::assertTrue($rehashing->isRunningFor(new GenericUser(['id' => 7, 'password' => $this->hash])));
    }

    /**
     * Where two guards' attempts validated the same user, the user is marked
     * when its stored hash verifies either attempt's password.
     *
     * @return void
     */
    public function testAUserValidatedByTwoAttemptsIsMarkedByEither(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        $rehashing->attempting('admin', ['password' => 'another password']);
        $rehashing->validated('admin', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::assertTrue($rehashing->isRunningFor($user));

        $rehashing->ended('web');

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * Rows of `[the credentials of an attempt]` that carry no password the
     * stored hash could verify.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideCredentialsWithoutAPassword(): iterable
    {
        yield 'no password' => [['email' => 'ada@example.test']];
        yield 'a password that is not a string' => [['password' => [self::PASSWORD]]];
    }

    /**
     * An attempt made without a password marks nothing, so whatever it saves is
     * answered as a change.
     *
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    #[DataProvider('provideCredentialsWithoutAPassword')]
    public function testAnAttemptWithoutAPasswordMarksNothing(array $credentials): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        $rehashing->attempting('web', $credentials);
        $rehashing->validated('web', $user);

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * A stored hash the application's hasher refuses to check, as a bcrypt
     * hasher with `verify` refuses a hash of another algorithm, verifies
     * nothing: the change is answered as one rather than failing the save.
     *
     * @return void
     */
    public function testAHashTheHasherRefusesToCheckVerifiesNothing(): void
    {
        Container::getInstance()->instance(Hasher::class, new BcryptHasher(['rounds' => 4, 'verify' => true]));

        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$cmVoYXNoZWQ']);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::assertFalse($rehashing->isRunningFor($user));
    }
}
