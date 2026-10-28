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

    /** @var string Another password. */
    private const string OTHER = 'another password';

    /** @var string A change of password that ran at once. */
    private const string CHANGE = 'change';

    /** @var string A change held as an open attempt's rehash, which a forced rehash then ran. */
    private const string HELD = 'held';

    /** @var string A change dropped as the package's own rehash. */
    private const string REHASH = 'rehash';

    /** @var \Illuminate\Container\Container|null The container before the test. */
    private ?Container $previous = null;

    /** @var \Illuminate\Hashing\BcryptHasher The hasher the mark checks a hash with. */
    private BcryptHasher $hasher;

    /** @var string A hash of the password. */
    private string $hash = '';

    /** @var string Another hash of the password, as a rehash saves. */
    private string $rehash = '';

    /** @var string A hash of another password. */
    private string $other = '';

    /**
     * Bind the hasher the mark checks a hash with.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previous = Container::getInstance();

        $this->hasher = new BcryptHasher(['rounds' => 4]);
        $container    = new Container;

        $container->instance(Hasher::class, $this->hasher);

        Container::setInstance($container);

        $this->hash   = $this->hasher->make(self::PASSWORD);
        $this->rehash = $this->hasher->make(self::PASSWORD);
        $this->other  = $this->hasher->make(self::OTHER);
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
        $user      = new GenericUser(['id' => 1, 'password' => $this->rehash]);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        self::assertSame('rehashed', $rehashing->during($user, function () use ($rehashing): string {
            self::assertSame(self::REHASH, $this->answer($rehashing, new GenericUser(['id' => '1', 'password' => 'another hash'])));
            self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 2, 'password' => 'another hash'])));
            self::assertSame(self::CHANGE, $this->answer($rehashing, new PlainIdentityFixture(1)));

            return 'rehashed';
        }));

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A nested rehash does not clear the outer one's mark.
     *
     * @return void
     */
    public function testANestedRehashKeepsTheOuterMark(): void
    {
        $outer     = new GenericUser(['id' => 1, 'password' => $this->rehash]);
        $inner     = new GenericUser(['id' => 2, 'password' => $this->rehash]);
        $rehashing = new Rehashing;

        $rehashing->during($outer, function () use ($rehashing, $outer, $inner): void {

            self::assertSame([self::REHASH, self::REHASH], $rehashing->during($inner, fn (): array => [$this->answer($rehashing, $outer), $this->answer($rehashing, $inner)]));

            self::assertSame(self::REHASH, $this->answer($rehashing, $outer));
            self::assertSame(self::CHANGE, $this->answer($rehashing, $inner));
        });

        self::assertSame(self::CHANGE, $this->answer($rehashing, $outer));
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
        $user      = new GenericUser(['id' => 1, 'password' => $this->rehash]);

        try {
            $rehashing->during($user, static function (): never {
                throw new \RuntimeException('rehash failed');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('rehash failed', $exception->getMessage());
        }

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A guard's attempt marks the user it validated, and no other, from the
     * validation until the attempt ends for that user.
     *
     * @return void
     */
    public function testAnAttemptMarksTheUserItValidatedUntilItEnds(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->validated('web', $user);

        self::assertSame(self::HELD, $this->answer($rehashing, new GenericUser(['id' => '7', 'password' => $this->rehash])));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 8, 'password' => $this->rehash])));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new PlainIdentityFixture(7, $this->rehash)));

        $rehashing->ended('admin', $user);
        $rehashing->ended('web', new GenericUser(['id' => 8]));

        self::assertSame(self::HELD, $this->answer($rehashing, $user));

        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * An attempt that found no one ends with no user, which closes the attempt
     * of the guard that validated no one.
     *
     * @return void
     */
    public function testAnAttemptThatFoundNoOneEndsWithNoUser(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->ended('web', null);
        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A validation outside an attempt, or by another guard than the one
     * attempting, marks nothing; nor does a second validation within an
     * attempt, as a callback's `validate()` of another user makes.
     *
     * @return void
     */
    public function testOnlyTheAttemptsOwnValidationMarks(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other     = new GenericUser(['id' => 8, 'password' => $this->rehash]);

        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->validated('web', $user);
        $rehashing->validated('web', $other);

        self::assertSame(self::HELD, $this->answer($rehashing, $user));
        self::assertSame(self::CHANGE, $this->answer($rehashing, $other));
    }

    /**
     * Inside an attempt, a save of its user is taken for the rehash only when
     * the hash before it and the hash it saved both verify the password the
     * attempt was made with: a new password, a change back to the attempt's
     * password, and a save over no hash are changes.
     *
     * @return void
     */
    public function testAnAttemptTakesOnlyASaveThatKeepsItsPasswordForTheRehash(): void
    {
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD]);
        $rehashing->validated('web', new GenericUser(['id' => 7, 'password' => $this->hash]));

        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->other])));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->rehash]), $this->other));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->rehash]), null));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => null])));
        self::assertSame(self::HELD, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->rehash])));
    }

    /**
     * A change of password and a change back, with a session started between
     * them, are both changes: neither is held, so neither waits on the attempt
     * that stays open around them, nor is dropped when it ends.
     *
     * @return void
     */
    public function testAChangeAndAChangeBackWhileAnAttemptIsOpenBothRun(): void
    {
        $rehashing = new Rehashing;
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', new GenericUser(['id' => 7, 'password' => $this->hash]));

        self::save($rehashing, new GenericUser(['id' => 7, 'password' => $this->other]), $this->hash, $runs, 'away');
        self::save($rehashing, new GenericUser(['id' => 7, 'password' => $this->rehash]), $this->other, $runs, 'back');

        self::assertSame(['away', 'back'], $runs->getArrayCopy());

        $rehashing->ended('web', new GenericUser(['id' => 7]));

        self::assertSame(['away', 'back'], $runs->getArrayCopy());
    }

    /**
     * Where two guards' attempts validated the same user, the user is marked
     * when its hashes verify either attempt's password.
     *
     * @return void
     */
    public function testAUserValidatedByTwoAttemptsIsMarkedByEither(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('admin', ['password' => self::OTHER]);
        $rehashing->validated('admin', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::assertSame(self::HELD, $this->answer($rehashing, $user));

        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * An attempt made inside another attempt's callback on the same guard ends
     * without ending the attempt around it, whether it validated another user,
     * found no one, or was refused for the same user: the outer attempt's own
     * rehash is still taken for one, until the outer attempt ends.
     *
     * @return void
     */
    public function testANestedAttemptOnTheSameGuardLeavesTheOuterOneOpen(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other     = new GenericUser(['id' => 8, 'password' => $this->other]);
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        $rehashing->attempting('web', ['password' => self::OTHER]);
        $rehashing->validated('web', $other);

        self::assertSame(self::HELD, $this->answer($rehashing, $other, $this->other));

        $rehashing->ended('web', $other);
        $rehashing->ended('web', $other);

        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->ended('web', null);

        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $other, $this->other));
        self::assertSame(self::HELD, $this->answer($rehashing, $user));

        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * Where an attempt inside another validated the same user, the save is held
     * for the inner attempt, so the inner attempt's end drops it; an attempt's
     * end for a user leaves the attempts inside it for other users open.
     *
     * @return void
     */
    public function testAnAttemptsEndClosesTheInnermostAttemptForItsUser(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other     = new GenericUser(['id' => 8, 'password' => $this->rehash]);
        $rehashing = new Rehashing;
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'inner rehash');

        $rehashing->ended('web', $user);
        $rehashing->forced($user);

        self::assertSame([], $runs->getArrayCopy());
        self::assertSame(self::HELD, $this->answer($rehashing, $user));

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
        self::assertSame(self::HELD, $this->answer($rehashing, $other));
    }

    /**
     * A new attempt of a guard closes every attempt left open at the top of the
     * guard that cannot be running around it, and drops what they held: one
     * that validated no one, one made without a password, and one that already
     * held a save as its rehash. An attempt that may still be running around it
     * stays open.
     *
     * @return void
     */
    public function testANewAttemptClosesTheAttemptsThatCannotEncloseIt(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other     = new GenericUser(['id' => 8, 'password' => $this->rehash]);
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->ended('web', $user);
        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', []);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->ended('web', $other);
        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', new GenericUser(['id' => 9]));

        self::save($rehashing, $other, $this->hash, $runs, 'other');
        self::save($rehashing, $user, $this->hash, $runs, 'user');

        $rehashing->ended('web', new GenericUser(['id' => 9]));
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->forced($user);
        $rehashing->forced($other);

        self::assertSame([], $runs->getArrayCopy());
    }

    /**
     * A save held by an attempt that is then closed, by its end or by a new
     * attempt it cannot enclose, is let go rather than kept for the rest of the
     * request or job.
     *
     * @return void
     */
    public function testAClosedAttemptLetsGoOfTheSaveItHeld(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $rehashing = new Rehashing;

        foreach ([static fn () => $rehashing->ended('web', $user), static fn () => $rehashing->attempting('web', ['password' => self::PASSWORD])] as $close) {

            $rehashing->attempting('web', ['password' => self::PASSWORD]);
            $rehashing->validated('web', $user);

            $change = static function (): void {};
            $held   = \WeakReference::create($change);

            $rehashing->unlessRehash($user, $this->hash, $change);

            unset($change);

            self::assertNotNull($held->get());

            $close();

            self::assertNull($held->get());
        }
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
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->forced($user);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'first');

        $rehashing->forced(new GenericUser(['id' => 8, 'password' => $this->rehash]));

        self::assertSame([], $runs->getArrayCopy());

        $rehashing->forced(new GenericUser(['id' => '7', 'password' => $this->rehash]));
        $rehashing->forced($user);

        self::assertSame(['first'], $runs->getArrayCopy());

        self::save($rehashing, $user, $this->hash, $runs, 'dropped');

        $rehashing->ended('web', $user);
        $rehashing->forced($user);

        self::assertSame(['first'], $runs->getArrayCopy());
    }

    /**
     * Only the latest change held for a user runs, even when an earlier one is
     * held by another attempt, and a held change of one user neither replaces
     * nor runs another's.
     *
     * @return void
     */
    public function testOnlyTheLatestChangeHeldForAUserRuns(): void
    {
        $rehashing = new Rehashing;
        $first     = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $second    = new GenericUser(['id' => 8, 'password' => $this->rehash]);
        $new       = new GenericUser(['id' => 7, 'password' => $this->other]);
        $changed   = new GenericUser(['id' => 7, 'password' => $this->hasher->make(self::OTHER)]);
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $first);
        $rehashing->attempting('admin', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $second);

        self::save($rehashing, $first, $this->hash, $runs, 'first, earlier');
        self::save($rehashing, $second, $this->hash, $runs, 'second');
        self::save($rehashing, $first, $this->hash, $runs, 'first, later');
        self::save($rehashing, $new, $this->rehash, $runs, 'first, changed');

        $rehashing->attempting('console', ['password' => self::OTHER]);
        $rehashing->validated('console', $new);

        self::save($rehashing, $changed, $this->other, $runs, 'first, latest');

        $rehashing->forced($first);
        $rehashing->forced($second);
        $rehashing->forced($first);

        self::assertSame(['first, changed', 'first, latest', 'second'], $runs->getArrayCopy());
    }

    /**
     * Rows of `[the credentials of an attempt]` that carry no password a hash
     * could verify.
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
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('web', $credentials);
        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A hash the application's hasher refuses to check, as a bcrypt hasher with
     * `verify` refuses a hash of another algorithm, verifies nothing: the
     * change is answered as one rather than failing the save.
     *
     * @return void
     */
    public function testAHashTheHasherRefusesToCheckVerifiesNothing(): void
    {
        Container::getInstance()->instance(Hasher::class, new BcryptHasher(['rounds' => 4, 'verify' => true]));

        $rehashing = new Rehashing;
        $argon     = '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$cmVoYXNoZWQ';

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', new GenericUser(['id' => 7]));

        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $argon])));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->rehash]), $argon));
    }

    /**
     * How the mark answers a save of the user's password over the previous hash
     * (by default, a hash of the attempts' password): run at once (`change`),
     * held as an open attempt's rehash and run by a forced rehash of the user
     * (`held`), or dropped as the package's own rehash (`rehash`).
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing  $rehashing
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $previous
     * @return string
     */
    private function answer(Rehashing $rehashing, Authenticatable $user, mixed $previous = false): string
    {
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        self::save($rehashing, $user, $previous === false ? $this->hash : $previous, $runs, 'run');

        $atOnce = $runs->getArrayCopy();

        $rehashing->forced($user);

        return match (true) {
            $atOnce               !== [] => self::CHANGE,
            $runs->getArrayCopy() !== [] => self::HELD,
            default                      => self::REHASH,
        };
    }

    /**
     * Save the user's password over the previous hash, recording the change
     * under the name when it runs.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing  $rehashing
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $previous
     * @param  \ArrayObject<int, string>  $runs
     * @param  string  $name
     * @return void
     */
    private static function save(Rehashing $rehashing, Authenticatable $user, mixed $previous, \ArrayObject $runs, string $name): void
    {
        $rehashing->unlessRehash($user, $previous, static function () use ($runs, $name): void {
            $runs->append($name);
        });
    }
}
