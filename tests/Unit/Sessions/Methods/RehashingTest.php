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

    /** @var string A save that did not run: held as an attempt's rehash, or dropped as the package's own. */
    private const string KEPT = 'kept';

    /** @var \Illuminate\Container\Container|null The container before the test. */
    private ?Container $previous = null;

    /** @var \Illuminate\Hashing\BcryptHasher The hasher the mark checks a hash with. */
    private BcryptHasher $hasher;

    /** @var string A hash of the password the hasher would rehash. */
    private string $hash = '';

    /** @var string Another hash of the password, as a rehash saves. */
    private string $rehash = '';

    /** @var string A hash of another password. */
    private string $other = '';

    /** @var string A hash of another password the hasher would rehash. */
    private string $outdated = '';

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

        $this->hash     = (new BcryptHasher(['rounds' => 5]))->make(self::PASSWORD);
        $this->rehash   = $this->hasher->make(self::PASSWORD);
        $this->other    = $this->hasher->make(self::OTHER);
        $this->outdated = (new BcryptHasher(['rounds' => 5]))->make(self::OTHER);
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
     * The package's own rehash drops a save of its user that re-encodes the
     * password it was given, through any instance, and no other save, only
     * while the callback runs, and the callback's result is returned; what it
     * drops is not held for a forced rehash.
     *
     * @return void
     */
    public function testThePackagesRehashMarksItsUserWhileTheCallbackRuns(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 1, 'password' => $this->rehash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        self::assertSame('rehashed', $rehashing->during($user, self::PASSWORD, function () use ($rehashing, $runs): string {
            self::save($rehashing, new GenericUser(['id' => '1', 'password' => $this->rehash]), $this->hash, $runs, 'rehash');

            self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => '1', 'password' => $this->other])));
            self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 2, 'password' => $this->rehash])));
            self::assertSame(self::CHANGE, $this->answer($rehashing, new PlainIdentityFixture(1, $this->rehash)));

            return 'rehashed';
        }));

        $rehashing->forced($user);

        self::assertSame([], $runs->getArrayCopy());
        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A forced rehash inside the package's own rehash, by a listener of the
     * rehash's save that signs the user's other devices out, runs the save it
     * held: the save the package's rehash takes is held, not dropped, until the
     * rehash returns, and a save held before the rehash stays held.
     *
     * @return void
     */
    public function testAForcedRehashInsideThePackagesRehashRunsItsSave(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->during($user, self::PASSWORD, function () use ($rehashing, $user, $runs): void {
            self::save($rehashing, $user, $this->hash, $runs, 'forced');

            $rehashing->forced($user);
        });

        self::assertSame(['forced'], $runs->getArrayCopy());

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'held before');

        $rehashing->during($user, self::PASSWORD, static fn (): null => null);
        $rehashing->forced($user);

        self::assertSame(['forced', 'held before'], $runs->getArrayCopy());
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

        $rehashing->during($outer, self::PASSWORD, function () use ($rehashing, $outer, $inner): void {

            $answers = $rehashing->during($inner, self::PASSWORD, fn (): array => [$this->answer($rehashing, $outer), $this->answer($rehashing, $inner)]);

            self::assertSame([self::KEPT, self::KEPT], $answers);

            self::assertSame(self::KEPT, $this->answer($rehashing, $outer));
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
            $rehashing->during($user, self::PASSWORD, static function (): never {
                throw new \RuntimeException('rehash failed');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('rehash failed', $exception->getMessage());
        }

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A guard's attempt marks the very instance it validated, from the
     * validation until an end for that instance: a save of another user, or of
     * the same key of another class, is a change, and an end for another
     * instance (another user's, or another instance of the same user, as a
     * session user resolved inside a callback carries) leaves it open.
     *
     * @return void
     */
    public function testAnAttemptMarksTheInstanceItValidatedUntilItsEnd(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->validated('web', $user);

        self::assertSame(self::KEPT, $this->answer($rehashing, $user));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 8, 'password' => $this->rehash])));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new PlainIdentityFixture(7, $this->rehash)));
        self::assertSame(self::CHANGE, $this->answer($rehashing, new class (['id' => 7, 'password' => $this->rehash]) extends GenericUser {}));

        $rehashing->ended('admin', $user);
        $rehashing->ended('web', new GenericUser(['id' => 8]));
        $rehashing->ended('web', new GenericUser(['id' => 7]));

        self::assertSame(self::KEPT, $this->answer($rehashing, $user));

        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A save of the user through another instance is a change, and from then on
     * the attempt takes no save for its rehash: a change back to its password
     * through the instance it validated, still holding the hash from before the
     * change, is a change too.
     *
     * @return void
     */
    public function testAChangeThroughAnotherInstanceEndsWhatTheAttemptTakesForItsRehash(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, new GenericUser(['id' => 7, 'password' => $this->other]), $this->hash, $runs, 'away');

        self::store($user, $this->rehash);

        self::save($rehashing, $user, $this->hash, $runs, 'back');

        $rehashing->ended('web', $user);

        self::assertSame(['away', 'back'], $runs->getArrayCopy());
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

        self::assertSame(self::KEPT, $this->answer($rehashing, $user));
        self::assertSame(self::CHANGE, $this->answer($rehashing, $other));
    }

    /**
     * Rows of `[the hash saved, the hash it replaced, whether the save is taken
     * for the rehash]` of the instance an attempt with the password validated.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool}>
     */
    public static function provideSavesOfTheValidatedInstance(): iterable
    {
        yield 'a fresh hash of the password' => ['rehash', 'hash', true];
        yield 'a new password' => ['other', 'hash', false];
        yield 'back to the password from another' => ['rehash', 'other', false];
        yield 'over no hash' => ['rehash', null, false];
        yield 'no hash' => [null, 'hash', false];
    }

    /**
     * A save of the instance an attempt validated is taken for its rehash only
     * when the hash it replaced and the hash it saved both verify the password
     * the attempt was made with.
     *
     * @param  ?string  $saved
     * @param  ?string  $replaced
     * @param  bool  $rehash
     * @return void
     */
    #[DataProvider('provideSavesOfTheValidatedInstance')]
    public function testAnAttemptTakesOnlyASaveThatKeepsItsPasswordForTheRehash(?string $saved, ?string $replaced, bool $rehash): void
    {
        $hashes    = ['hash' => $this->hash, 'rehash' => $this->rehash, 'other' => $this->other];
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->hash]);

        $rehashing->attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::store($user, $saved === null ? null : $hashes[$saved]);

        self::assertSame($rehash ? self::KEPT : self::CHANGE, $this->answer($rehashing, $user, $replaced === null ? null : $hashes[$replaced]));
    }

    /**
     * Where two guards' attempts validated the same instance, a save is taken
     * for the rehash of either whose password both hashes verify.
     *
     * @return void
     */
    public function testAnInstanceValidatedByTwoAttemptsIsMarkedByEither(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('admin', ['password' => self::OTHER]);
        $rehashing->validated('admin', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::assertSame(self::KEPT, $this->answer($rehashing, $user));

        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * An attempt made inside another attempt's callback on the same guard ends
     * without ending the attempt around it, whether it validated another user,
     * found no one, was refused for the same user, or signed in another
     * instance of the same user with `Login` and then `Authenticated`: the
     * outer attempt's own rehash is still taken for one, until it ends.
     *
     * @return void
     */
    public function testANestedAttemptOnTheSameGuardLeavesTheOuterOneOpen(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $again     = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other     = new GenericUser(['id' => 8, 'password' => $this->other]);
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        $rehashing->attempting('web', ['password' => self::OTHER]);
        $rehashing->validated('web', $other);

        self::assertSame(self::KEPT, $this->answer($rehashing, $other, $this->outdated));

        $rehashing->ended('web', $other);
        $rehashing->ended('web', $other);

        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->ended('web', null);

        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->ended('web', $user);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $again);

        self::assertSame(self::KEPT, $this->answer($rehashing, $again));

        $rehashing->ended('web', $again);
        $rehashing->ended('web', $again);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $other, $this->outdated));
        self::assertSame(self::KEPT, $this->answer($rehashing, $user));

        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * An attempt's end closes the innermost attempt for its instance, past an
     * attempt inside it for another instance, which stays open; validating an
     * instance again lets go of the guard's earlier attempt for it.
     *
     * @return void
     */
    public function testAnAttemptsEndClosesTheInnermostAttemptForItsInstance(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other     = new GenericUser(['id' => 8, 'password' => $this->rehash]);
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
        self::assertSame(self::KEPT, $this->answer($rehashing, $other));

        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
        self::assertSame(self::KEPT, $this->answer($rehashing, $other));
    }

    /**
     * A new attempt of a guard lets go of every attempt of the guard that
     * cannot be running around it: one that validated no one, and one made
     * without a password. An attempt that may still be running around it stays
     * open, and a save held for it stays held: a forced rehash's save, whose
     * `OtherDeviceLogout` follows only after the save's other listeners (which
     * may make an attempt) have run, still runs.
     *
     * @return void
     */
    public function testANewAttemptLetsGoOfTheAttemptsThatCannotEncloseIt(): void
    {
        $user  = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $other = new GenericUser(['id' => 8, 'password' => $this->rehash]);
        $last  = new GenericUser(['id' => 9]);

        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->ended('web', $user);
        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', []);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->ended('web', $other);
        $rehashing->ended('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));

        $rehashing = new Rehashing;

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $other);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $last);

        self::save($rehashing, $other, $this->hash, $runs, 'other');
        self::save($rehashing, $user, $this->hash, $runs, 'user');

        $rehashing->ended('web', $last);
        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->ended('web', $user);
        $rehashing->forced($user);
        $rehashing->forced($other);

        self::assertSame(['user', 'other'], $runs->getArrayCopy());
    }

    /**
     * Letting go of an attempt from the middle of a guard's attempts leaves the
     * others in order, so the end of a later attempt still closes that attempt.
     *
     * @return void
     */
    public function testAnAttemptAfterOneLetGoOfStillEnds(): void
    {
        $outer     = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $middle    = new GenericUser(['id' => 8, 'password' => $this->rehash]);
        $inner     = new GenericUser(['id' => 9, 'password' => $this->rehash]);
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $outer);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $middle);

        self::assertSame(self::CHANGE, $this->answer($rehashing, new GenericUser(['id' => 7, 'password' => $this->other])));

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->ended('web', null);
        $rehashing->validated('web', $inner);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $inner));
        self::assertSame(self::KEPT, $this->answer($rehashing, $middle));
    }

    /**
     * A held save is let go of rather than kept for the rest of the request or
     * job once a forced rehash runs it, and, for the package's own rehash, once
     * that rehash returns.
     *
     * @return void
     */
    public function testAHeldSaveIsLetGoOf(): void
    {
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $rehashing = new Rehashing;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        $change = static function (): void {};
        $held   = \WeakReference::create($change);

        $rehashing->unlessRehash($user, $this->hash, $change);

        unset($change);

        self::assertNotNull($held->get());

        $rehashing->forced($user);

        self::assertNull($held->get());

        $rehashing->during($user, self::PASSWORD, function () use ($rehashing, $user, &$held): void {
            $change = static function (): void {};
            $held   = \WeakReference::create($change);

            $rehashing->unlessRehash($user, $this->hash, $change);
        });

        self::assertNull($held->get());
    }

    /**
     * Nothing a listener of the forced save may do before `OtherDeviceLogout`
     * drops the held save: end the attempt for the instance saved (binding it
     * to a guard fires `Authenticated`), make another attempt, or change the
     * password in a transaction it then rolls back.
     *
     * @return void
     */
    public function testAHeldSaveOutlivesTheEndOfItsAttempt(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'forced');

        $rehashing->ended('web', $user);
        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->forced($user);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'forced, after a change');
        self::save($rehashing, new GenericUser(['id' => 7, 'password' => $this->other]), $this->hash, $runs, 'rolled back');

        $rehashing->attempting('web', ['password' => 'wrong']);
        $rehashing->forced($user);

        self::assertSame(['forced', 'rolled back', 'forced, after a change'], $runs->getArrayCopy());
    }

    /**
     * The end of an attempt for another instance of the user leaves the save
     * held for the instance saved, so a forced rehash still runs it.
     *
     * @return void
     */
    public function testTheEndOfAnAttemptForAnotherInstanceKeepsTheHeldSave(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);
        $again     = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);
        $rehashing->attempting('admin', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $again);

        self::save($rehashing, $user, $this->hash, $runs, 'forced');

        $rehashing->ended('admin', $again);
        $rehashing->forced($again);

        self::assertSame(['forced'], $runs->getArrayCopy());
    }

    /**
     * A change of the user's password through another instance leaves the save
     * held for an attempt held, since that change may yet be rolled back: a
     * later forced rehash still runs it.
     *
     * @return void
     */
    public function testAChangeLeavesTheSaveHeldForTheUser(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'rehash');
        self::save($rehashing, new GenericUser(['id' => 7, 'password' => $this->other]), $this->hash, $runs, 'change');

        $rehashing->forced(new GenericUser(['id' => 7, 'password' => $this->other]));

        self::assertSame(['change', 'rehash'], $runs->getArrayCopy());
    }

    /**
     * The instance an attempt validated, once it stands for another user (its
     * key changed, as an Eloquent model moved to another connection does), is
     * that other user: its save is a change.
     *
     * @return void
     */
    public function testTheValidatedInstanceMovedToAnotherUserIsThatUser(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $this->rehash]);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        $user->__set('id', 8);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user));
    }

    /**
     * A change held as an open attempt's rehash runs when the user's password
     * is then forced (`logoutOtherDevices()`) through any instance of the user,
     * and only once; that sign-out is a change, so a save of the instance the
     * attempt validated is a change from then on. A forced rehash of another
     * user, or with nothing held, runs nothing, and a later attempt's rehash,
     * held to the end of the request or job, runs at a later sign-out too.
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

        self::save($rehashing, $user, $this->hash, $runs, 'after the sign-out');

        self::assertSame(['first', 'after the sign-out'], $runs->getArrayCopy());

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::save($rehashing, $user, $this->hash, $runs, 'rehash');

        $rehashing->ended('web', $user);
        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->forced($user);

        self::assertSame(['first', 'after the sign-out', 'rehash'], $runs->getArrayCopy());
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

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $first);
        $rehashing->attempting('admin', ['password' => self::PASSWORD]);
        $rehashing->validated('admin', $second);

        self::save($rehashing, $first, $this->hash, $runs, 'first, earlier');
        self::save($rehashing, $second, $this->hash, $runs, 'second');
        self::save($rehashing, $first, $this->hash, $runs, 'first, later');

        $rehashing->attempting('console', ['password' => self::OTHER]);
        $rehashing->validated('console', $first);

        self::store($first, $this->other);

        self::save($rehashing, $first, $this->outdated, $runs, 'first, latest');

        $rehashing->forced($first);
        $rehashing->forced($second);
        $rehashing->forced($first);

        self::assertSame(['first, latest', 'second'], $runs->getArrayCopy());
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
     * Rows of `[whether the saved hash, rather than the replaced one, is of
     * another algorithm]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideHashesOfAnotherAlgorithm(): iterable
    {
        yield 'the saved hash' => [true];
        yield 'the replaced hash' => [false];
    }

    /**
     * A hash the application's hasher refuses to check, as a bcrypt hasher with
     * `verify` refuses a hash of another algorithm, verifies nothing: the
     * change is answered as one rather than failing the save.
     *
     * @param  bool  $saved
     * @return void
     */
    #[DataProvider('provideHashesOfAnotherAlgorithm')]
    public function testAHashTheHasherRefusesToCheckVerifiesNothing(bool $saved): void
    {
        $argon = '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$cmVoYXNoZWQ';

        Container::getInstance()->instance(Hasher::class, new BcryptHasher(['rounds' => 4, 'verify' => true]));

        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7, 'password' => $saved ? $argon : $this->rehash]);

        $rehashing->attempting('web', ['password' => self::PASSWORD]);
        $rehashing->validated('web', $user);

        self::assertSame(self::CHANGE, $this->answer($rehashing, $user, $saved ? $this->hash : $argon));
    }

    /**
     * How the mark answers a save of the user's password over the replaced hash
     * (by default, a hash of the attempts' password): run at once (`change`),
     * or not (`kept`: held as an open attempt's rehash, or dropped as the
     * package's own).
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing  $rehashing
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $replaced
     * @return string
     */
    private function answer(Rehashing $rehashing, Authenticatable $user, mixed $replaced = false): string
    {
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        self::save($rehashing, $user, $replaced === false ? $this->hash : $replaced, $runs, 'run');

        return $runs->getArrayCopy() === [] ? self::KEPT : self::CHANGE;
    }

    /**
     * Give the user the hash, as a save of its password does.
     *
     * @param  \Illuminate\Auth\GenericUser  $user
     * @param  ?string  $hash
     * @return void
     */
    private static function store(GenericUser $user, ?string $hash): void
    {
        $user->__set('password', $hash);
    }

    /**
     * Save the user's password over the replaced hash, recording the change
     * under the name when it runs.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing  $rehashing
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $replaced
     * @param  \ArrayObject<int, string>  $runs
     * @param  string  $name
     * @return void
     */
    private static function save(Rehashing $rehashing, Authenticatable $user, mixed $replaced, \ArrayObject $runs, string $name): void
    {
        $rehashing->unlessRehash($user, $replaced, static function () use ($runs, $name): void {
            $runs->append($name);
        });
    }
}
