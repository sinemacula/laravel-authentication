<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Methods;

use Illuminate\Auth\GenericUser;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
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

    /** @var string A change of password that ran at once. */
    private const string CHANGE = 'change';

    /** @var string A change held as an open attempt's rehash, which a forced rehash then ran. */
    private const string HELD = 'held';

    /** @var string A change dropped as the package's own rehash. */
    private const string REHASH = 'rehash';

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

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));

        self::assertSame('rehashed', $rehashing->during($user, static function () use ($rehashing): string {
            self::assertSame(self::REHASH, self::answer($rehashing, new GenericUser(['id' => '1', 'password' => 'another hash'])));
            self::assertSame(self::CHANGE, self::answer($rehashing, new GenericUser(['id' => 2, 'password' => 'another hash'])));
            self::assertSame(self::CHANGE, self::answer($rehashing, new PlainIdentityFixture(1)));

            return 'rehashed';
        }));

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
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

            self::assertSame([self::REHASH, self::REHASH], $rehashing->during($inner, static fn (): array => [self::answer($rehashing, $outer), self::answer($rehashing, $inner)]));

            self::assertSame(self::REHASH, self::answer($rehashing, $outer));
            self::assertSame(self::CHANGE, self::answer($rehashing, $inner));
        });

        self::assertSame(self::CHANGE, self::answer($rehashing, $outer));
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

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
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

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));

        $rehashing->validated('web', $user);

        self::assertSame(self::HELD, self::answer($rehashing, new GenericUser(['id' => '7', 'password' => $this->hash])));
        self::assertSame(self::CHANGE, self::answer($rehashing, new GenericUser(['id' => 8, 'password' => $this->hash])));
        self::assertSame(self::CHANGE, self::answer($rehashing, new PlainIdentityFixture(7, $this->hash)));

        $rehashing->ended('admin');

        self::assertSame(self::HELD, self::answer($rehashing, $user));

        $rehashing->ended('web');

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));

        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
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

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $user);

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));

        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
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

        self::assertSame(self::CHANGE, self::answer($rehashing, new GenericUser(['id' => 7, 'password' => (new BcryptHasher(['rounds' => 4]))->make('a new password')])));
        self::assertSame(self::CHANGE, self::answer($rehashing, new GenericUser(['id' => 7, 'password' => null])));
        self::assertSame(self::HELD, self::answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->hash])));
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

        self::assertSame(self::HELD, self::answer($rehashing, $user));

        $rehashing->ended('web');

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
    }

    /**
     * A change held as an open attempt's rehash runs only when the user's
     * password is then forced (`logoutOtherDevices()`), and only once; the
     * attempt's end drops it, as a rehash; a forced rehash of another user, or
     * with nothing held, runs nothing.
     *
     * @return void
     */
    public function testAHeldChangeRunsOnlyWhenTheUsersPasswordIsForced(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->forced($user);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        $rehashing->unlessRehash($user, static function () use ($runs): void {
            $runs[] = 'first';
        });

        $rehashing->forced(new GenericUser(['id' => 8, 'password' => $this->hash]));

        self::assertSame([], $runs->getArrayCopy());

        $rehashing->forced(new GenericUser(['id' => '7', 'password' => $this->hash]));
        $rehashing->forced($user);

        self::assertSame(['first'], $runs->getArrayCopy());

        $rehashing->unlessRehash($user, static function () use ($runs): void {
            $runs[] = 'dropped';
        });

        $rehashing->ended('web');
        $rehashing->forced($user);

        self::assertSame(['first'], $runs->getArrayCopy());
    }

    /**
     * Only the latest change held for a user runs, and a held change of one
     * user neither replaces nor runs another's.
     *
     * @return void
     */
    public function testOnlyTheLatestChangeHeldForAUserRuns(): void
    {
        $rehashing = new Rehashing;
        $first     = new GenericUser(['id' => 7, 'password' => $this->hash]);
        $second    = new GenericUser(['id' => 8, 'password' => $this->hash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $first);
        $rehashing->attempting('admin', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $second);

        foreach (['first, earlier' => $first, 'second' => $second, 'first, latest' => $first] as $name => $user) {
            $rehashing->unlessRehash($user, static function () use ($runs, $name): void {
                $runs[] = $name;
            });
        }

        $rehashing->forced($first);
        $rehashing->forced($second);

        self::assertSame(['first, latest', 'second'], $runs->getArrayCopy());
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

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
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

        self::assertSame(self::CHANGE, self::answer($rehashing, $user));
    }

    /**
     * How the mark answers a change of the user's password: run at once
     * (`change`), held as an open attempt's rehash and run by a forced rehash
     * of the user (`held`), or dropped as the package's own rehash (`rehash`).
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing  $rehashing
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return string
     */
    private static function answer(Rehashing $rehashing, Authenticatable $user): string
    {
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->unlessRehash($user, static function () use ($runs): void {
            $runs->append('run');
        });

        $atOnce = $runs->getArrayCopy();

        $rehashing->forced($user);

        return match (true) {
            $atOnce               !== [] => self::CHANGE,
            $runs->getArrayCopy() !== [] => self::HELD,
            default                      => self::REHASH,
        };
    }
}
