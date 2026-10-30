<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Auth\Events\Logout;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Jwt\DeviceOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The context a test acts as on each package guard, kept in the container so it
 * outlives the request a test sends through the HTTP kernel.
 *
 * Each request the kernel handles is bound into the container, and every guard
 * the package creates rebinds itself to it and starts over. A guard acted on
 * gets one more `request` rebinding callback, registered after the guard's own,
 * that binds the context again through the guard's trusted `authenticateAs()`,
 * so the request is authenticated as the test acted. Nothing else changes: a
 * queued job a worker runs still starts signed out, as in production, and the
 * next request acts again.
 *
 * Acting on a guard ends with `forget()` (which the trait's `stopActing()`
 * calls), with Laravel's `Logout` for the guard (a sign-out the request made),
 * or when a new context replaces it. It is tied to the guard instance acted on,
 * so a guard forgotten and created afresh (`Auth::forgetGuards()`) is not acted
 * on until the test acts again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActingContext
{
    /** @var array<string, array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, principal: \SineMacula\Laravel\Authentication\Contracts\Principal, device: ?\SineMacula\Laravel\Authentication\Contracts\Device, scopes: ?list<string>}> The context acted as, by guard name. */
    private array $acting = [];

    /** @var array<string, \SineMacula\Laravel\Authentication\Guards\AbstractGuard> The guard instance, by name, whose request rebinding binds the context again. */
    private array $wired = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Container\Container  $container
     */
    private function __construct(

        /** The application the guards live in. */
        private readonly Container $container,
    ) {}

    /**
     * The acting context of the application, created, bound and listening for
     * `Logout` the first time it is asked for.
     *
     * @return self
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function current(): self
    {
        $container = Container::getInstance();

        if ($container->bound(self::class)) {

            /** @var self */
            return $container->make(self::class);
        }

        $context = new self($container);

        $container->instance(self::class, $context);

        $container->make(Dispatcher::class)->listen(Logout::class, static function (Logout $event) use ($context): void {
            $context->forget($event->guard);
        });

        return $context;
    }

    /**
     * Resolve the named package guard, or the default one, or fail saying the
     * guard is not one the helpers can act on.
     *
     * @param  ?string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     *
     * @throws \InvalidArgumentException
     */
    public static function guard(?string $name): AbstractGuard
    {
        /** @var \Illuminate\Auth\AuthManager $auth */
        $auth  = Container::getInstance()->make('auth');
        $guard = $auth->guard($name);

        if (!$guard instanceof AbstractGuard) {
            $message = sprintf('Auth guard [%s] is not a package guard (jwt or api_key), so a test cannot act on it with these helpers.', $name ?? $auth->getDefaultDriver());

            throw new \InvalidArgumentException($message);
        }

        return $guard;
    }

    /**
     * The principal a test acting as the identity acts as when it names none:
     * the guard resolver's default, or an `InvalidArgumentException`, as
     * `setUser()` fails, when the identity has none.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \InvalidArgumentException
     */
    public static function defaultPrincipal(AbstractGuard $guard, Identity $identity): Principal
    {
        $principal = $guard->getPrincipalResolver()->resolve($identity);

        if ($principal === null) {
            $message = sprintf('Guard %s could not resolve a default principal for identity %s; name the principal to act as.', $guard->getName(), $identity::class);

            throw new \InvalidArgumentException($message);
        }

        return $principal;
    }

    /**
     * The identity and principal a device's session acts as on the guard: the
     * owner it records, found through the guard's provider, and the principal
     * it records, found through the guard's resolver (its default when the
     * device records none). An `InvalidArgumentException` says what could not
     * be found.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}
     *
     * @throws \InvalidArgumentException
     */
    public static function recordedOn(AbstractGuard $guard, EloquentDevice&Model $device): array
    {
        $ownerKey = DeviceOwnership::ownerKey($device);
        $identity = $ownerKey === null ? null : $guard->getProvider()->retrieveById($ownerKey);

        if (!$identity instanceof Identity || !DeviceOwnership::isOwner($device, $identity)) {
            throw new \InvalidArgumentException(sprintf('Device [%s] has no owner the provider of guard [%s] finds.', self::key($device), $guard->getName()));
        }

        $recorded = $device->getAttribute(PrincipalReference::columns($device)[1]);

        if ($recorded === null) {
            return [$identity, self::defaultPrincipal($guard, $identity)];
        }

        $principal = $guard->getPrincipalResolver()->resolve($identity, $recorded);

        if ($principal === null || !PrincipalReference::isRecordedOn($device, $principal)) {
            throw new \InvalidArgumentException(sprintf('The resolver of guard [%s] does not resolve the principal device [%s] records.', $guard->getName(), self::key($device)));
        }

        return [$identity, $principal];
    }

    /**
     * Assert that the guard has the subject bound: nothing when nothing is
     * expected, otherwise the expected instance or one of the same class with
     * the same identifier.
     *
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  ?object  $expected
     * @param  mixed  $expectedId
     * @param  ?object  $actual
     * @param  mixed  $actualId
     * @return void
     *
     * @throws \PHPUnit\Framework\ExpectationFailedException
     */
    public static function assertBound(string $kind, AbstractGuard $guard, ?object $expected, mixed $expectedId, ?object $actual, mixed $actualId): void
    {
        $matches = $expected === null ? $actual === null : self::matches($expected, $expectedId, $actual, $actualId);
        $wanted  = self::describe($expected, $expectedId);
        $found   = self::describe($actual, $actualId);

        Assert::assertTrue($matches, sprintf('Expected the %s bound to guard [%s] to be %s, got %s.', $kind, $guard->getName(), $wanted, $found));
    }

    /**
     * Act as the context on the guard: bind it now and again on every request
     * the guard is rebound to, until the acting ends. A context the guard
     * refuses to bind (scopes for an identity that is not a machine) is not
     * kept.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?list<string>  $scopes
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function act(AbstractGuard $guard, Identity $identity, Principal $principal, ?Device $device, ?array $scopes = null): void
    {
        $name = $guard->getName();

        $guard->authenticateAs($identity, $principal, $device, $scopes);

        $this->acting[$name] = ['identity' => $identity, 'principal' => $principal, 'device' => $device, 'scopes' => $scopes];

        if (($this->wired[$name] ?? null) === $guard) {
            return;
        }

        $this->wired[$name] = $guard;

        $this->container->rebinding('request', function () use ($guard): void {
            $this->bind($guard);
        });
    }

    /**
     * Stop acting on the guard: the next request it serves is authenticated by
     * its own credential, if any.
     *
     * @param  string  $guard
     * @return void
     */
    public function forget(string $guard): void
    {
        unset($this->acting[$guard]);
    }

    /**
     * Bind the context acted as on the guard, when the guard is still the one
     * acted on.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return void
     */
    private function bind(AbstractGuard $guard): void
    {
        $name   = $guard->getName();
        $acting = $this->acting[$name] ?? null;

        if ($acting === null || $this->wired[$name] !== $guard) {
            return;
        }

        $guard->authenticateAs($acting['identity'], $acting['principal'], $acting['device'], $acting['scopes']);
    }

    /**
     * Whether the subject bound is the one expected: the same instance, or one
     * of the same class with an identifier equal to the expected one's.
     *
     * @param  object  $expected
     * @param  mixed  $expectedId
     * @param  ?object  $actual
     * @param  mixed  $actualId
     * @return bool
     */
    private static function matches(object $expected, mixed $expectedId, ?object $actual, mixed $actualId): bool
    {
        if ($actual === $expected) {
            return true;
        }

        return $actual !== null && $actual::class === $expected::class && IdentifierCoercion::matches($actualId, $expectedId);
    }

    /**
     * The device's key, for a message.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @return ?string
     */
    private static function key(Model $device): ?string
    {
        return IdentifierCoercion::stringify($device->getKey());
    }

    /**
     * Describe a bound subject for an assertion's message.
     *
     * @param  ?object  $subject
     * @param  mixed  $identifier
     * @return string
     */
    private static function describe(?object $subject, mixed $identifier): string
    {
        return $subject === null ? 'none' : sprintf('%s [%s]', $subject::class, IdentifierCoercion::stringify($identifier) ?? 'no identifier');
    }
}
