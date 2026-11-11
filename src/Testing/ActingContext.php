<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Auth\Events\Logout;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The context a test acts as on each package guard, kept in the container so it
 * outlives the request a test sends through the HTTP kernel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActingContext
{
    /** @var array<string, array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, principal: \SineMacula\Laravel\Authentication\Contracts\Principal, session: ?\SineMacula\Laravel\Authentication\Contracts\Session, scopes: ?list<string>, tenant: ?\SineMacula\Laravel\Authentication\Contracts\Tenant}> The context acted as, by guard name. */
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
     * Resolve the named package guard, or the default one.
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
     * The guard resolver's default principal for the identity.
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
     * The identity and principal the session records, found through the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}
     *
     * @throws \InvalidArgumentException
     */
    public static function recordedOn(AbstractGuard $guard, EloquentSession&Model $session): array
    {
        $ownerKey = SessionOwnership::ownerKey($session);
        $identity = $ownerKey === null ? null : $guard->getProvider()->retrieveById($ownerKey);

        if (!$identity instanceof Identity || !SessionOwnership::isOwner($session, $identity)) {
            throw new \InvalidArgumentException(sprintf('Session [%s] has no owner the provider of guard [%s] finds.', self::key($session), $guard->getName()));
        }

        $recorded = $session->getAttribute(PrincipalReference::columns($session)[1]);

        if ($recorded === null) {
            return [$identity, self::defaultPrincipal($guard, $identity)];
        }

        $principal = $guard->getPrincipalResolver()->resolve($identity, $recorded);

        if ($principal === null || !PrincipalReference::isRecordedOn($session, $principal)) {
            throw new \InvalidArgumentException(sprintf('The resolver of guard [%s] does not resolve the principal session [%s] records.', $guard->getName(), self::key($session)));
        }

        return [$identity, $principal];
    }

    /**
     * Assert that the guard has the expected subject bound, or none.
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
     * Act as the context on the guard, now and on every request until the
     * acting ends.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function act(AbstractGuard $guard, Identity $identity, Principal $principal, ?Session $session, ?array $scopes = null, ?Tenant $tenant = null): void
    {
        $name = $guard->getName();

        $guard->authenticateAs($identity, $principal, $session, $scopes, $tenant);

        $this->acting[$name] = ['identity' => $identity, 'principal' => $principal, 'session' => $session, 'scopes' => $scopes, 'tenant' => $tenant];

        if (($this->wired[$name] ?? null) === $guard) {
            return;
        }

        $this->wired[$name] = $guard;

        $this->container->rebinding('request', function () use ($guard): void {
            $this->bind($guard);
        });
    }

    /**
     * Act in the tenant with the context the guard is acted as.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function actIn(AbstractGuard $guard, Tenant $tenant): void
    {
        $acting = $this->acting[$guard->getName()] ?? null;

        if ($acting === null || ($this->wired[$guard->getName()] ?? null) !== $guard) {
            throw new \InvalidArgumentException(sprintf('The test does not act on guard [%s]: act as an identity, a principal or a session first.', $guard->getName()));
        }

        $this->act($guard, $acting['identity'], $acting['principal'], $acting['session'], $acting['scopes'], $tenant);
    }

    /**
     * Stop acting on the guard.
     *
     * @param  string  $guard
     * @return void
     */
    public function forget(string $guard): void
    {
        unset($this->acting[$guard]);
    }

    /**
     * Bind the context again, when the guard is still the one acted on.
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

        $guard->authenticateAs($acting['identity'], $acting['principal'], $acting['session'], $acting['scopes'], $acting['tenant']);
    }

    /**
     * Whether the subject bound is the expected instance or shares its class
     * and identifier.
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
     * The session's key, for a message.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return ?string
     */
    private static function key(Model $session): ?string
    {
        return IdentifierCoercion::stringify($session->getKey());
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
