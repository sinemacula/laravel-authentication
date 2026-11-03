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
 * Unit tests for telling the two bearer credential forms apart and for which
 * guard a route that lists both leaves a credential to.
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
     * Rows of `[credential, jwt form]`: anything with a dot is a JWT's,
     * anything without one an API key's, however malformed.
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
     * kind's credential to it and keeps its own.
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
     * A route listing guards of one kind only, however many, leaves nothing to
     * anyone: each guard reads every credential.
     *
     * @return void
     */
    public function testARouteListingOneKindLeavesNothing(): void
    {
        self::assertFalse(BearerForms::defersTo(BearerForms::JWT, self::routeListing(['api', 'console']), self::KEY));
        self::assertFalse(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine']), self::JWT));
    }

    /**
     * A request no `auth` middleware recorded guards for, or one recording
     * something other than a list, leaves nothing.
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
     * The configuration is read only for a credential of the other kind's form
     * on a request the `auth` middleware recorded guards for: a guard reading
     * its own kind's credential, or one on a request with no record, needs no
     * configuration bound at all.
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
     * A name that is not configured, a guard of another driver, or a guards
     * configuration that is not a map, leaves nothing.
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
     * A guard name containing a dot is read as one name, not as a path into the
     * configuration.
     *
     * @return void
     */
    public function testAGuardNameWithADotIsOneName(): void
    {
        $this->configure(['auth.guards' => ['machine' => ['driver' => 'api_key'], 'v1.api' => ['driver' => 'jwt']]]);

        self::assertTrue(BearerForms::defersTo(BearerForms::API_KEY, self::routeListing(['machine', 'v1.api']), self::JWT));
    }

    /**
     * Only a string names a guard: a recorded name or a default guard that is
     * not one leaves nothing, even where the guards configuration holds a guard
     * of the other kind under that key.
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
     * The class holds no state and cannot be instantiated: its constructor is
     * private. Reflection invokes it so the line is covered while still
     * documenting the access modifier.
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
     * Bind a configuration of `jwt` guards `api` (the default) and `console`,
     * an `api_key` guard `machine`, a session guard `web`, and a malformed
     * `broken`, with the overrides, in a container of its own.
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
