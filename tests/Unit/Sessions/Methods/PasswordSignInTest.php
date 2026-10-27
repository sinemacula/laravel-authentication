<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Methods;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Auth\Authenticatable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Unit tests for the password sign-in method: the configured identifier key,
 * the input `authenticate()` passes to the provider, and the credential checks
 * `attempt()` and `validate()` share.
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

    /**
     * Build a fresh provider mock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
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
        self::assertSame('email', (new PasswordSignIn(new Repository))->identifierType());
        self::assertSame('username', $this->method('username')->identifierType());
        self::assertSame('login_2', $this->method('login_2')->identifierType());
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

        $this->method($key)->identifierType();
    }

    /**
     * The identifier is the input's value under the configured key, as given,
     * and only when it is a string.
     *
     * @return void
     */
    public function testIdentifierIsTheStringUnderTheConfiguredKey(): void
    {
        $method = $this->method('username');

        self::assertSame(' Ada ', $method->identifier(['username' => ' Ada ', 'email' => 'ada@example.test']));
        self::assertNull($method->identifier(['email' => 'ada@example.test']));
        self::assertNull($method->identifier(['username' => 42]));
        self::assertNull($method->identifier(['username' => ['ada']]));
    }

    /**
     * `authenticate()` passes the provider only the identifier and the
     * password, so no other input key reaches a query, and returns the identity
     * whose password matches.
     *
     * @return void
     */
    public function testAuthenticatePassesOnlyTheIdentifierAndPassword(): void
    {
        $identity    = \Mockery::mock(Identity::class);
        $credentials = ['email' => 'ada@example.test', 'password' => 'secret'];

        $this->provider->shouldReceive('retrieveByCredentials')->once()->with($credentials)->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->with($identity, $credentials)->andReturnTrue();

        $input = [
            'email'     => 'ada@example.test',
            'password'  => 'secret',
            'is_admin'  => true,
            'tenant_id' => 7,
        ];

        self::assertSame($identity, $this->method('email')->authenticate($this->request($input)));
    }

    /**
     * Input whose identifier or password is not a string is passed on as
     * `null`, which the provider looks up and validates as nothing, so the
     * sign-in fails as invalid credentials.
     *
     * @return void
     */
    public function testAuthenticatePassesNonStringValuesAsNull(): void
    {
        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => null, 'password' => null])
            ->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        $outcome = $this->method('email')->authenticate($this->request(['email' => ['ada'], 'password' => 1234]));

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $outcome);
    }

    /**
     * A wrong password fails as invalid credentials.
     *
     * @return void
     */
    public function testAuthenticateRejectsAWrongPassword(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->once()->andReturnFalse();

        $outcome = $this->method('email')->authenticate($this->request(['email' => 'ada@example.test', 'password' => 'wrong']));

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $outcome);
    }

    /**
     * `verifyCredentials()` hands the provider the caller's credentials
     * untouched, closures included, and returns the identity whose password
     * matches.
     *
     * @return void
     */
    public function testVerifyCredentialsKeepsTheCallersCredentials(): void
    {
        $identity    = \Mockery::mock(Identity::class);
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
     * `retrieve()` returns whatever account the credentials name, whether or
     * not the password matches, and `accepts()` checks the password only for an
     * account that exists.
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
     * Build a sign-in request for the input.
     *
     * @param  array<string, mixed>  $input
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInRequest
     */
    private function request(array $input): SignInRequest
    {
        return new SignInRequest('api', $this->provider, $input, new ClientContext('203.0.113.7', 'agent'));
    }
}
