<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Methods;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Stringable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the password sign-in method.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordSignIn::class)]
final class PasswordSignInTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The guard's identity provider. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AttemptLimiter The attempt limiter the sign-in's account attempts use. */
    private MockInterface $limiter;

    /**
     * Build a provider mock and a limiter that grants every account attempt.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->limiter  = \Mockery::mock(AttemptLimiter::class);

        $this->limiter->shouldReceive('acquire')
            ->byDefault()
            ->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, null));
        $this->limiter->shouldReceive('release')->never();
    }

    /**
     * The method is registered and recorded as `password`.
     *
     * @return void
     */
    public function testIsNamedPassword(): void
    {
        self::assertSame('password', PasswordSignIn::NAME);
    }

    /**
     * Without configuration the identifier is `email`; a configured column name
     * replaces it.
     *
     * @return void
     */
    public function testIdentifierTypeIsTheConfiguredColumnOrEmail(): void
    {
        self::assertSame('email', (new PasswordSignIn(new Repository))->identifierType('api'));
        self::assertSame('username', $this->method('username')->identifierType('api'));
        self::assertSame('login_2', $this->method('login_2')->identifierType('api'));
    }

    /**
     * Rows of `[configured value]` that do not name a lower-case identifier
     * column, or name one that holds a password.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideInvalidIdentifierKeys(): iterable
    {
        yield from [
            'null'                  => [null],
            'empty'                 => [''],
            'not a string'          => [['email']],
            'upper case'            => ['Email'],
            'leading digit'         => ['1email'],
            'leading underscore'    => ['_email'],
            'dotted'                => ['users.email'],
            'trailing newline'      => ["email\n"],
            'contains password'     => ['email_password'],
            'is password'           => ['password'],
            'punctuation'           => ['e-mail'],
            'leading space'         => [' email'],
            'unicode letter'        => ['émail'],
            'internal space'        => ['e mail'],
            'only underscore'       => ['_'],
            'password at the start' => ['password_hint'],
        ];
    }

    /**
     * A configured identifier key that is not a lower-case column name, or that
     * contains `password`, fails closed naming the setting.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideInvalidIdentifierKeys')]
    public function testIdentifierTypeRejectsAMalformedKey(mixed $key): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.sign_in.password_identifier must name the identifier column');

        $this->method($key)->identifierType('api');
    }

    /**
     * A guard may name its own identifier column in its `sign_in` block;
     * otherwise the package's is used.
     *
     * @return void
     */
    public function testAGuardMayNameItsOwnIdentifierColumn(): void
    {
        $method = new PasswordSignIn(new Repository([
            'authentication' => ['sign_in' => ['password_identifier' => 'email']],
            'auth'           => ['guards' => [
                'staff'   => ['driver' => 'jwt', 'sign_in' => ['password_identifier' => 'username']],
                'members' => ['driver' => 'jwt', 'sign_in' => []],
                'api'     => ['driver' => 'jwt'],
            ]],
        ]));

        self::assertSame('username', $method->identifierType('staff'));
        self::assertSame('email', $method->identifierType('members'));
        self::assertSame('email', $method->identifierType('api'));
        self::assertSame('email', $method->identifierType('unconfigured'));
        self::assertSame('ada', $method->identifier('staff', ['username' => 'ada', 'email' => 'ada@example.test']));
        self::assertSame('ada@example.test', $method->identifier('api', ['username' => 'ada', 'email' => 'ada@example.test']));
    }

    /**
     * A guard's own identifier column must be a lower-case column name too, and
     * the failure names the guard's setting.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideInvalidIdentifierKeys')]
    public function testAGuardsOwnIdentifierColumnIsValidatedToo(mixed $key): void
    {
        $method = new PasswordSignIn(new Repository(['auth' => ['guards' => ['staff' => ['sign_in' => ['password_identifier' => $key]]]]]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('auth.guards.staff.sign_in.password_identifier must name the identifier column');

        $method->identifierType('staff');
    }

    /**
     * Rows of `[guard sign_in block]` that a guard may not set.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedGuardSignInBlocks(): iterable
    {
        yield from [
            'not an array' => ['username'],
            'unknown key'  => [['password_identifier' => 'username', 'pending_ttl_seconds' => 300]],
            'list'         => [['username']],
        ];
    }

    /**
     * A guard's `sign_in` block that is not an array, or that sets anything but
     * the identifier column, fails closed naming the guard.
     *
     * @param  mixed  $block
     * @return void
     */
    #[DataProvider('provideMalformedGuardSignInBlocks')]
    public function testAMalformedGuardSignInBlockFailsClosed(mixed $block): void
    {
        $method = new PasswordSignIn(new Repository(['auth' => ['guards' => ['staff' => ['sign_in' => $block]]]]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('auth.guards.staff.sign_in must be an array that sets only `password_identifier`.');

        $method->identifierType('staff');
    }

    /**
     * The identifier is the string or integer under the configured key, as a
     * string; anything else names none.
     *
     * @return void
     */
    public function testIdentifierIsTheStringOrIntegerUnderTheConfiguredKey(): void
    {
        $method = $this->method('username');

        self::assertSame(' Ada ', $method->identifier('api', ['username' => ' Ada ', 'email' => 'ada@example.test']));
        self::assertNull($method->identifier('api', ['email' => 'ada@example.test']));
        self::assertSame('42', $method->identifier('api', ['username' => 42]));
        self::assertNull($method->identifier('api', ['username' => 4.2]));
        self::assertNull($method->identifier('api', ['username' => ['ada']]));
    }

    /**
     * A password answers no challenge, whatever the input carries.
     *
     * @return void
     */
    public function testAPasswordAnswersNoChallenge(): void
    {
        self::assertNull($this->method('email')->challenge(['email' => 'ada@example.test', 'challenge' => '0195f4a2-7b1c-4000-8000-00000000000a']));
    }

    /**
     * `authenticate()` passes the provider only the identifier and the
     * password.
     *
     * @return void
     */
    public function testAuthenticatePassesOnlyTheIdentifierAndPassword(): void
    {
        $identity    = $this->identity();
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret'];

        $this->provider->shouldReceive('retrieveByCredentials')->once()->with($credentials)->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->with($identity, $credentials)->andReturnTrue();

        $input = [
            'email'     => 'ada@example.test',
            'password'  => 'secret',
            'is_admin'  => true,
            'tenant_id' => 7,
        ];

        $verified = $this->method('email')->authenticate($this->request($input));

        self::assertInstanceOf(FirstFactor::class, $verified);
        self::assertSame($identity, $verified->identity);
        self::assertSame(ChannelKind::PASSWORD, $verified->channel->kind);
        self::assertNull($verified->channel->reference);
        self::assertEquals(new ObservedProperties, $verified->observed);
        self::assertSame(['pwd'], $verified->methods);
    }

    /**
     * An identifier that is not a string is refused without a lookup, and a
     * non-string password is passed as `null`.
     *
     * @return void
     */
    public function testAuthenticateRefusesAnIdentifierThatIsNotAStringWithoutALookup(): void
    {
        $identity = $this->identity();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => 'ada@example.test', 'password' => null])
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->with($identity, ['email' => 'ada@example.test', 'password' => null])->andReturnFalse();

        $method = $this->method('email');

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $method->authenticate($this->request(['email' => ['ada'], 'password' => 'secret'])));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $method->authenticate($this->request(['password' => 'secret'])));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $method->authenticate($this->request(['email' => 'ada@example.test', 'password' => 1234])));
    }

    /**
     * `authenticate()` counts the password check against the account before
     * comparing the password.
     *
     * @return void
     */
    public function testAuthenticateCountsThePasswordCheckAgainstTheAccount(): void
    {
        $identity    = $this->identity();
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret'];
        $subjects    = [];

        $this->limiter->shouldReceive('acquire')->twice()->andReturnUsing(static function (AttemptSubject $subject) use (&$subjects): AttemptReservation {
            $subjects[] = $subject;

            return new AttemptReservation($subject, count($subjects) === 2 ? 60 : null);
        });
        $this->provider->shouldReceive('retrieveByCredentials')->twice()->with($credentials)->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->with($identity, $credentials)->andReturnTrue();

        $method = $this->method('email');

        self::assertSame($identity, self::verifiedIdentity($method->authenticate($this->request($credentials, 'staff'))));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $method->authenticate($this->request($credentials, 'staff')));

        self::assertSame('staff', $subjects[0]->guard);
        self::assertSame(AttemptFlow::SIGN_IN, $subjects[0]->flow);
        self::assertNull($subjects[0]->identifier);
        self::assertNull($subjects[0]->identifierType);
        self::assertNull($subjects[0]->ip);
        self::assertSame(AccountAttempts::account($identity), $subjects[0]->account);
    }

    /**
     * A non-human identity has no password: every check refuses it before its
     * account is counted or its password compared, whatever it stores.
     *
     * @return void
     */
    public function testAMachineIdentityHasNoPassword(): void
    {
        $machine = \Mockery::mock(MachineIdentity::class);
        $machine->shouldReceive('getAuthIdentifier')->andReturn(7);

        $credentials = ['email' => 'robot@example.test', 'password' => 'secret'];

        $this->limiter->shouldNotReceive('acquire');
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($machine);
        $this->provider->shouldNotReceive('validateCredentials');

        $method = $this->method('email');

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $method->authenticate($this->request($credentials)));
        self::assertNull($method->verifyCredentials($this->provider, $credentials));
        self::assertFalse($method->accepts($this->provider, $machine, $credentials));
        self::assertFalse($method->verifyPassword(new AccountAttempts($this->limiter, 'api'), $this->provider, $machine, $credentials));
    }

    /**
     * `attempt()` counts the password check against the account before
     * comparing the password.
     *
     * @return void
     */
    public function testVerifyPasswordCountsTheCheckAgainstTheAccount(): void
    {
        $identity    = $this->identity();
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret'];
        $subjects    = [];

        $this->limiter->shouldReceive('acquire')->times(3)->andReturnUsing(static function (AttemptSubject $subject) use (&$subjects): AttemptReservation {
            $subjects[] = $subject;

            return new AttemptReservation($subject, count($subjects) === 3 ? 60 : null, ['account' => "window {$subject->guard}"]);
        });
        $this->provider->shouldReceive('validateCredentials')->twice()->with($identity, $credentials)->andReturn(true, false);

        $method   = $this->method('email');
        $attempts = new AccountAttempts($this->limiter, 'staff');

        self::assertTrue($method->verifyPassword($attempts, $this->provider, $identity, $credentials));
        self::assertFalse($method->verifyPassword($attempts, $this->provider, $identity, $credentials));
        self::assertFalse($method->verifyPassword($attempts, $this->provider, $identity, $credentials));

        self::assertSame([['account' => 'window staff'], ['account' => 'window staff']], $attempts->windows());
        self::assertSame('staff', $subjects[0]->guard);
        self::assertSame(AccountAttempts::account($identity), $subjects[0]->account);
    }

    /**
     * `attempt()` looks credentials up only when the identifier is a string,
     * `Stringable`, integer or closure.
     *
     * @return void
     */
    public function testOnlyAStringAStringableAnIntegerOrAClosureIsLookedUp(): void
    {
        $method     = $this->method('email');
        $stringable = new Stringable('ada@example.test');
        $closure    = static fn (): null => null;

        self::assertSame(['email' => 'ada@example.test', 'password' => 'x'], $method->lookupCredentials('api', ['email' => 'ada@example.test', 'password' => 'x']));
        self::assertSame(['email' => $stringable], $method->lookupCredentials('api', ['email' => $stringable]));
        self::assertSame(['email' => $closure], $method->lookupCredentials('api', ['email' => $closure]));
        self::assertSame(['id' => 7, 'password' => 'x'], $method->lookupCredentials('api', ['id' => 7, 'password' => 'x']));
        self::assertSame(['email' => '0', 'password' => 'x'], $method->lookupCredentials('api', ['email' => 0, 'password' => 'x']));
        self::assertNull($method->lookupCredentials('api', ['email' => ['ada@example.test']]));
        self::assertNull($method->lookupCredentials('api', ['email' => 1.0]));
        self::assertNull($method->lookupCredentials('api', ['email' => null]));
        self::assertNull($method->lookupCredentials('api', ['email' => true]));
        self::assertSame('ada@example.test', $method->identifier('api', ['email' => $stringable]));
    }

    /**
     * A wrong password fails as invalid credentials.
     *
     * @return void
     */
    public function testAuthenticateRejectsAWrongPassword(): void
    {
        $identity = $this->identity();

        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->andReturnFalse();

        $outcome = $this->method('email')->authenticate($this->request(['email' => 'ada@example.test', 'password' => 'wrong']));

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $outcome);
    }

    /**
     * `verifyCredentials()` hands the provider the caller's credentials
     * untouched.
     *
     * @return void
     */
    public function testVerifyCredentialsKeepsTheCallersCredentials(): void
    {
        $identity    = $this->identity();
        $scope       = static fn (): null => null;
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret', 'active' => $scope];

        $this->provider->shouldReceive('retrieveByCredentials')->once()->with($credentials)->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->with($identity, $credentials)->andReturnTrue();

        self::assertSame($identity, $this->method('email')->verifyCredentials($this->provider, $credentials));
    }

    /**
     * An account that is not an `Identity` is never verified, even with the
     * right password, and its password is not checked.
     *
     * @return void
     */
    public function testVerifyCredentialsRejectsAnAccountThatIsNotAnIdentity(): void
    {
        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturn(\Mockery::mock(Authenticatable::class));
        $this->provider->shouldNotReceive('validateCredentials');

        self::assertNull($this->method('email')->verifyCredentials($this->provider, ['email' => 'x', 'password' => 'y']));
    }

    /**
     * An unknown identifier is not verified and no password is checked.
     *
     * @return void
     */
    public function testVerifyCredentialsRejectsAnUnknownIdentifier(): void
    {
        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        self::assertNull($this->method('email')->verifyCredentials($this->provider, ['email' => 'x', 'password' => 'y']));
    }

    /**
     * `retrieve()` returns the account the credentials name, and `accepts()`
     * checks its password.
     *
     * @return void
     */
    public function testRetrieveAndAcceptsSplitTheLookupFromThePasswordCheck(): void
    {
        $user        = \Mockery::mock(Authenticatable::class);
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret'];

        $this->provider->shouldReceive('retrieveByCredentials')->once()->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->once()->with($user, $credentials)->andReturnFalse();

        $method = $this->method('email');

        self::assertSame($user, $method->retrieve($this->provider, $credentials));
        self::assertFalse($method->accepts($this->provider, $user, $credentials));
        self::assertFalse($method->accepts($this->provider, null, $credentials));
    }

    /**
     * Rows of `[hashing.rehash_on_login, whether the provider is asked]`, the
     * setting read as Laravel's own guards read it.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideRehashSettings(): iterable
    {
        yield from [
            'on'           => [true, true],
            'off'          => [false, false],
            'off as zero'  => [0, false],
            'off as empty' => ['', false],
            'on as one'    => ['1', true],
        ];
    }

    /**
     * `rehash()` asks the provider to rehash unless Laravel's `rehash_on_login`
     * turns it off.
     *
     * @param  mixed  $setting
     * @param  bool  $asked
     * @return void
     */
    #[DataProvider('provideRehashSettings')]
    public function testRehashFollowsLaravelsRehashOnLoginSetting(mixed $setting, bool $asked): void
    {
        $identity    = $this->identity();
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret'];

        $this->provider->shouldReceive('rehashPasswordIfRequired')->times($asked ? 1 : 0)->with($identity, $credentials);

        (new PasswordSignIn(new Repository(['hashing' => ['rehash_on_login' => $setting]])))->rehash($this->provider, $identity, $credentials);
    }

    /**
     * The rehash runs marked by the container's shared `Rehashing`, so a
     * listener can tell it from a change.
     *
     * @return void
     */
    public function testRehashRunsMarkedAsAnAutomaticRehash(): void
    {
        $rehashing = new Rehashing;
        $previous  = Container::getInstance();
        $container = new Container;
        $hasher    = new BcryptHasher(['rounds' => 4]);
        $outdated  = (new BcryptHasher(['rounds' => 5]))->make('secret');
        $identity  = new PlainIdentityFixture(1, $hasher->make('secret'));

        $container->instance(Rehashing::class, $rehashing);
        $container->instance(Hasher::class, $hasher);

        Container::setInstance($container);

        $changes = [];

        $this->provider->shouldReceive('rehashPasswordIfRequired')->once()->andReturnUsing(static function () use ($rehashing, $identity, $outdated, &$changes): void {
            $rehashing->unlessRehash($identity, $outdated, static function () use (&$changes): void {
                $changes[] = 'during';
            });
        });

        try {
            (new PasswordSignIn(new Repository))->rehash($this->provider, $identity, ['password' => 'secret']);

            $rehashing->forced($identity);
            $rehashing->unlessRehash($identity, $outdated, static function () use (&$changes): void {
                $changes[] = 'after';
            });
        } finally {
            Container::setInstance($previous);
        }

        self::assertSame(['after'], $changes);
    }

    /**
     * Without the setting, the password is rehashed, as Laravel's default.
     *
     * @return void
     */
    public function testRehashIsOnByDefault(): void
    {
        $identity = $this->identity();

        $this->provider->shouldReceive('rehashPasswordIfRequired')->once()->with($identity, ['password' => 'secret']);

        (new PasswordSignIn(new Repository))->rehash($this->provider, $identity, ['password' => 'secret']);
    }

    /**
     * Neither `authenticate()` nor `verifyCredentials()` rehashes: only an
     * admitted sign-in does, through `rehash()`.
     *
     * @return void
     */
    public function testVerifyingNeverRehashes(): void
    {
        $identity = $this->identity();

        $this->provider->shouldReceive('retrieveByCredentials')->twice()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->twice()->andReturnTrue();
        $this->provider->shouldNotReceive('rehashPasswordIfRequired');

        $method = $this->method('email');

        self::assertSame($identity, $method->verifyCredentials($this->provider, ['email' => 'x', 'password' => 'y']));
        self::assertSame($identity, self::verifiedIdentity($method->authenticate($this->request(['email' => 'x', 'password' => 'y']))));
    }

    /**
     * Build an identity whose auth identifier is 7.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(): MockInterface
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        return $identity;
    }

    /**
     * Build the method with the given identifier key configured.
     *
     * @param  mixed  $identifier
     * @return \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn
     */
    private function method(mixed $identifier): PasswordSignIn
    {
        return new PasswordSignIn(new Repository(['authentication' => ['sign_in' => ['password_identifier' => $identifier]]]));
    }

    /**
     * Build a sign-in request for the input to the guard, whose account checks
     * the test's limiter counts.
     *
     * @param  array<string, mixed>  $input
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInRequest
     */
    private function request(array $input, string $guard = 'api'): SignInRequest
    {
        return new SignInRequest($guard, $this->provider, $input, new ClientContext('203.0.113.7', 'agent'), (new AccountAttempts($this->limiter, $guard))->reserve(...));
    }

    /**
     * The identity a sign-in method's answer verified, failing the test when it
     * verified none.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor  $verified
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function verifiedIdentity(FailureReason|FirstFactor $verified): Identity
    {
        self::assertInstanceOf(FirstFactor::class, $verified);

        return $verified->identity;
    }
}
