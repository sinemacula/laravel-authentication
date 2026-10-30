<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Passkeys\WebAuthn;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Providers\DeferredFactorPolicyProvider;
use Tests\Fixtures\Sessions\ProvenIdentitySignIn;

/**
 * Feature tests for the order the package's service provider and another
 * package's provider register in: every binding the package makes is a default,
 * kept out of the way of one made before it and replaced by one made after, on
 * a container that holds only the two providers' bindings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class ProviderBindingOrderTest extends TestCase
{
    /**
     * Rows of `[abstract]`: every abstract the package's provider binds.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBoundAbstracts(): iterable
    {
        $abstracts = [
            PrincipalResolver::class,
            AudiencePolicy::class,
            AttemptLimiter::class,
            AdditionalFactorPolicy::class,
            ScopeRegistry::class,
            BreachedPasswordChecker::class,
            PasswordResetLinkSender::class,
            IdentifierNormalisers::class,
            SignInMethodManager::class,
            Rehashing::class,
            WebAuthn::class,
            JwtTokenServiceFactory::class,
            IlluminateAuthenticate::class,
        ];

        foreach ($abstracts as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * A binding another package made before the package's provider registers is
     * kept: the package's default does not replace it.
     *
     * @param  string  $abstract
     * @return void
     */
    #[DataProvider('provideBoundAbstracts')]
    public function testABindingMadeBeforeThePackageRegistersIsKept(string $abstract): void
    {
        $container = self::container();
        $sibling   = new \stdClass;

        self::siblingBinding($container, $abstract, $sibling)->register();
        (new AuthenticationServiceProvider($container))->register();

        self::assertSame($sibling, $container->make($abstract));
    }

    /**
     * A binding another package makes after the package's provider registers
     * replaces the default, as any later binding does.
     *
     * @param  string  $abstract
     * @return void
     */
    #[DataProvider('provideBoundAbstracts')]
    public function testABindingMadeAfterThePackageRegistersReplacesTheDefault(string $abstract): void
    {
        $container = self::container();
        $sibling   = new \stdClass;

        (new AuthenticationServiceProvider($container))->register();
        self::siblingBinding($container, $abstract, $sibling)->register();

        self::assertSame($sibling, $container->make($abstract));
    }

    /**
     * A sign-in method registry another package bound and extended before the
     * package's provider registers keeps its method.
     *
     * @return void
     */
    public function testASignInMethodRegistryBoundEarlierKeepsItsMethods(): void
    {
        $container = self::container();

        $sibling = new class ($container) extends ServiceProvider {
            /**
             * Bind the registry and register a method on it.
             *
             * @return void
             */
            #[\Override]
            public function register(): void
            {
                $this->app->singleton(SignInMethodManager::class);
                $this->app->make(SignInMethodManager::class)->extend('sibling', fn (): ProvenIdentitySignIn => new ProvenIdentitySignIn);
            }
        };

        $sibling->register();
        (new AuthenticationServiceProvider($container))->register();

        self::assertContains('sibling', $container->make(SignInMethodManager::class)->names());
    }

    /**
     * A sign-in method another package registers once the registry resolves,
     * from a provider that registers before the package's, is on the package's
     * registry.
     *
     * @return void
     */
    public function testASignInMethodRegisteredOnResolutionBeforeThePackageIsKept(): void
    {
        $container = self::container();

        $sibling = new class ($container) extends ServiceProvider {
            /**
             * Register a method once the registry resolves.
             *
             * @return void
             */
            #[\Override]
            public function register(): void
            {
                $this->callAfterResolving(SignInMethodManager::class, static function (SignInMethodManager $methods): void {
                    $methods->extend('sibling', fn (): ProvenIdentitySignIn => new ProvenIdentitySignIn);
                });
            }
        };

        $sibling->register();
        (new AuthenticationServiceProvider($container))->register();

        $methods = $container->make(SignInMethodManager::class);

        self::assertContains('sibling', $methods->names());
        self::assertSame($methods, $container->make(SignInMethodManager::class));
    }

    /**
     * An additional-factor policy a deferred provider offers is loaded in place
     * of the default when the policy is first resolved, as Laravel installs
     * deferred services after registering the eager providers.
     *
     * @return void
     */
    public function testADeferredProvidersFactorPolicyIsLoadedInPlaceOfTheDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->addDeferredServices([AdditionalFactorPolicy::class => DeferredFactorPolicyProvider::class]);

        self::assertInstanceOf(AlwaysRequireAdditionalFactor::class, $app->make(AdditionalFactorPolicy::class));
    }

    /**
     * A policy bound with `singleton()` after the default has resolved still
     * replaces it, as the container drops the resolved instance.
     *
     * @return void
     */
    public function testALaterBindingReplacesADefaultThatHasResolved(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertInstanceOf(NeverRequireAdditionalFactor::class, $app->make(AdditionalFactorPolicy::class));

        $app->singleton(AdditionalFactorPolicy::class, AlwaysRequireAdditionalFactor::class);

        self::assertInstanceOf(AlwaysRequireAdditionalFactor::class, $app->make(AdditionalFactorPolicy::class));
    }

    /**
     * A deferred provider is not loaded for a default that has already
     * resolved: Laravel loads one only for a service with no instance yet, so
     * the default stays.
     *
     * @return void
     */
    public function testADeferredProvidersFactorPolicyIsNotLoadedOnceTheDefaultHasResolved(): void
    {
        $app = $this->app;

        assert($app !== null);

        $default = $app->make(AdditionalFactorPolicy::class);

        $app->addDeferredServices([AdditionalFactorPolicy::class => DeferredFactorPolicyProvider::class]);

        self::assertInstanceOf(NeverRequireAdditionalFactor::class, $default);
        self::assertSame($default, $app->make(AdditionalFactorPolicy::class));
    }

    /**
     * Register the package service provider against the Testbench application.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class];
    }

    /**
     * A container holding nothing but itself and a configuration repository,
     * which the package's provider merges its configuration into.
     *
     * @return \Illuminate\Container\Container
     */
    private static function container(): Container
    {
        $container = new Container;
        $container->instance(ContainerContract::class, $container);
        $container->instance('config', new ConfigRepository);

        return $container;
    }

    /**
     * Another package's provider, binding the abstract to the object.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $abstract
     * @param  object  $object
     * @return \Illuminate\Support\ServiceProvider
     */
    private static function siblingBinding(Container $container, string $abstract, object $object): ServiceProvider
    {
        return new class ($container, $abstract, $object) extends ServiceProvider {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Container\Container  $app
             * @param  string  $abstract
             * @param  object  $object
             */
            public function __construct(

                // Container the provider binds into.
                Container $app,

                /** Abstract the provider binds. */
                private readonly string $abstract,

                /** Object the abstract resolves to. */
                private readonly object $object,
            ) {
                parent::__construct($app);
            }

            /**
             * Bind the abstract to the object.
             *
             * @return void
             */
            #[\Override]
            public function register(): void
            {
                $object = $this->object;

                $this->app->singleton($this->abstract, static fn (): object => $object);
            }
        };
    }
}
