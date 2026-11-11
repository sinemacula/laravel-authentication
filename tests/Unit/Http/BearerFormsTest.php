<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as RepositoryContract;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\BearerForms;

/**
 * Unit tests for telling the two bearer credential forms apart on a route.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerForms::class)]
final class BearerFormsTest extends TestCase
{
    /** @var string A credential in API key form. */
    private const string KEY = 'ak_abcdefghijklmnop_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';

    /** @var string A credential in JWT form: three base64url segments. */
    private const string JWT = 'aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl';

    /** @var ?\Illuminate\Container\Container The container in place before the test. */
    private ?Container $previous = null;

    /**
     * Bind the guards' configuration in a container of the test's own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previous = Container::getInstance();

        $this->configure();
    }

    /**
     * Restore the container in place before the test.
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
     * Rows of `[credential, jwt form]`: a credential with a dot is a JWT's,
     * however malformed.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideCredentials(): iterable
    {
        yield from [
            'compact JWS'           => [self::JWT, true],
            'one dot'               => ['header.payload', true],
            'three dots'            => ['a.b.c.d', true],
            'a lone dot'            => ['.', true],
            'empty signature'       => ['a.b.', true],
            'dotted key'            => [self::KEY . '.', true],
            'API key'               => [self::KEY, false],
            'truncated key'         => ['ak_abcdefghijklmnop_ABC', false],
            'dotless JWT fragment'  => ['aGVhZGVy', false],
            'anything else dotless' => ['not-a-key', false],
        ];
    }

    /**
     * A credential is in JWT form exactly when it contains a dot.
     *
     * @param  string  $credential
     * @param  bool  $jwtForm
     * @return void
     */
    #[DataProvider('provideCredentials')]
    public function testTellsTheFormsApartByTheDot(string $credential, bool $jwtForm): void
    {
        self::assertSame($jwtForm, BearerForms::isJwtForm($credential));
    }

    /**
     * On a route listing a guard of each kind, each guard leaves the other
     * kind's credential to it.
     *
     * @return void
     */
    public function testEachGuardLeavesTheOtherKindsCredentialOnARouteListingBoth(): void
    {
        $request = self::routeListing(['api', 'machine']);

        self::assertTrue(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));
        self::assertTrue(BearerForms::defersTo(BearerForms::JWT, $request, self::KEY));
        self::assertFalse(BearerForms::defersTo(BearerForms::JWT, $request, self::JWT));
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, $request, self::KEY));
    }

    /**
     * The order the route lists them in does not matter.
     *
     * @return void
     */
    public function testTheOrderTheRouteListsThemInDoesNotMatter(): void
    {
        $request = self::routeListing(['machine', 'api']);

        self::assertTrue(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));
        self::assertTrue(BearerForms::defersTo(BearerForms::JWT, $request, self::KEY));
    }

    /**
     * A route listing guards of one kind only leaves nothing to anyone.
     *
     * @return void
     */
    public function testARouteListingOneKindLeavesNothing(): void
    {
        self::assertFalse(BearerForms::defersTo(BearerForms::JWT, self::routeListing(['api', 'console']), self::KEY));
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine']), self::JWT));
    }

    /**
     * A request without a recorded list of guards leaves nothing.
     *
     * @return void
     */
    public function testARequestWithoutARecordLeavesNothing(): void
    {
        $request = Request::create('/');

        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));

        $request->attributes->set(BearerForms::ROUTE_GUARDS, 'api');

        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));
    }

    /**
     * The configuration is read only when a credential of the other kind's form
     * needs deciding.
     *
     * @return void
     */
    public function testReadsTheConfigurationOnlyWhenItMustDecide(): void
    {
        Container::setInstance(new Container);

        self::assertFalse(BearerForms::defersTo(BearerForms::JWT, self::routeListing(['api', 'machine']), self::JWT));
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['api', 'machine']), self::KEY));
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, Request::create('/'), self::JWT));

        $this->expectException(BindingResolutionException::class);

        BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['api', 'machine']), self::JWT);
    }

    /**
     * A `null` name is the default guard, as for the `auth` middleware.
     *
     * @return void
     */
    public function testANullNameIsTheDefaultGuard(): void
    {
        $request = self::routeListing([null, 'machine']);

        self::assertTrue(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));

        $this->configure(['auth.defaults.guard' => 'web']);

        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));

        $this->configure(['auth.defaults.guard' => null]);

        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));
    }

    /**
     * An unknown guard, a guard of another driver or a malformed guards map
     * leaves nothing.
     *
     * @return void
     */
    public function testAGuardThatIsNotConfiguredOrOfAnotherDriverLeavesNothing(): void
    {
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine', 'missing', 'web']), self::JWT));
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine', 'broken']), self::JWT));

        $this->configure(['auth.guards' => 'api']);

        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine', 'api']), self::JWT));
    }

    /**
     * A guard name containing a dot is read as one name.
     *
     * @return void
     */
    public function testAGuardNameWithADotIsOneName(): void
    {
        $this->configure(['auth.guards' => ['machine' => ['driver' => 'api_key'], 'v1.api' => ['driver' => 'jwt']]]);

        self::assertTrue(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine', 'v1.api']), self::JWT));
    }

    /**
     * Only a string names a guard, even where the configuration holds one under
     * that key.
     *
     * @return void
     */
    public function testANameThatIsNotAStringNamesNoGuard(): void
    {
        $this->configure(['auth.guards' => [7 => ['driver' => 'jwt']], 'auth.defaults.guard' => 7]);

        $request = Request::create('/');

        $request->attributes->set(BearerForms::ROUTE_GUARDS, [7, ['api'], null]);

        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, $request, self::JWT));
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(BearerForms::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(BearerForms::class, $instance);
    }

    /**
     * A request whose route lists the guards.
     *
     * @param  list<?string>  $guards
     * @return \Illuminate\Http\Request
     */
    private static function routeListing(array $guards): Request
    {
        $request = Request::create('/');

        $request->attributes->set(BearerForms::ROUTE_GUARDS, $guards);

        return $request;
    }

    /**
     * Bind a configuration of `jwt`, `api_key`, session and malformed guards,
     * with the overrides.
     *
     * @param  array<string, mixed>  $overrides
     * @return void
     */
    private function configure(array $overrides = []): void
    {
        $config = new Repository(['auth' => [
            'defaults' => ['guard' => 'api'],
            'guards'   => [
                'api'     => ['driver' => 'jwt'],
                'console' => ['driver' => 'jwt'],
                'machine' => ['driver' => 'api_key'],
                'web'     => ['driver' => 'session'],
                'broken'  => 'jwt',
            ],
        ]]);

        foreach ($overrides as $key => $value) {
            $config->set($key, $value);
        }

        $container = new Container;
        $container->instance(RepositoryContract::class, $config);

        Container::setInstance($container);
    }
}
