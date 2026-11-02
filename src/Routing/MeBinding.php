<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Routing;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Http\ConsumerMessages;
use SineMacula\Laravel\Authentication\Routing\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * The `me` route binding of a session, identity or principal model that uses
 * `ResolvesMeRouteBinding`, against the caller the route's credential proves
 * (`CallerCredentials`).
 *
 * The model's kind decides what it binds: a session model a session, an
 * identity model (one that is its own principal included) an identity, any
 * other principal model a principal. `me` is the caller's own instance of that
 * kind, when it is one of the model's class, and an `AuthenticationException`
 * for the guard (a `401`) when there is none. Any other value goes to the
 * model's own lookup, run with every read on the write connection; a miss stays
 * a miss, a request with no caller finds nothing, and what is found must agree
 * with the credential or is a miss too: an identity must be the caller's; a
 * session must be owned by the caller's identity and, for a refresh or a
 * pending credential, be the very session the credential proves; a principal
 * must be the caller's current one, one of the principals a pending session
 * records or offers, or, for a guard that keeps sessions, one the caller's
 * identity may use the application as (with the identifier type its session
 * records).
 *
 * A scoped child binding resolves the same way when the child's model uses the
 * trait too, through the parent's relationship, and a `me` child must be within
 * it; otherwise the parent's own lookup runs unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MeBinding
{
    /** @var string The value that binds the caller's own instance. */
    public const string ME = 'me';

    /** @var string The kind of a session model. */
    private const string SESSION = 'session';

    /** @var string The kind of an identity model. */
    private const string IDENTITY = 'identity';

    /** @var string The kind of a principal model. */
    private const string PRINCIPAL = 'principal';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Routing\CallerCredentials  $callers
     * @param  \Illuminate\Http\Request  $request
     */
    public function __construct(

        /** Reads the request's caller from the credential its route declares. */
        private CallerCredentials $callers,

        /** The request whose route parameters are being bound. */
        private Request $request,
    ) {}

    /**
     * The binding for the request the container serves now, through the
     * package's auth manager.
     *
     * @return self
     *
     * @throws \LogicException
     */
    public static function current(): self
    {
        $app  = Container::getInstance();
        $auth = $app->make('auth');

        if (!$auth instanceof AuthManager) {
            throw new \LogicException(sprintf('The me route binding needs the package\'s auth manager as `auth`; %s is bound.', get_debug_type($auth)));
        }

        return new self(new CallerCredentials($auth, $app->make(Repository::class), $app->make(Dispatcher::class)), $app->make('request'));
    }

    /**
     * Bind the route value to an instance of the model: the caller's own for
     * `me`, otherwise what the model's own lookup finds when it agrees with the
     * caller's credential.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  mixed  $value
     * @param  \Closure(): mixed  $lookup
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function resolve(Model $model, mixed $value, \Closure $lookup): ?Model
    {
        $kind = self::kind($model);

        if ($value === self::ME) {
            return $this->own($model, $kind);
        }

        return $this->found($model, $kind, $lookup);
    }

    /**
     * Bind the route value to a child through the parent's relationship: as a
     * top-level binding, within the relationship, when the child's model uses
     * the trait; otherwise the parent's own child lookup, unchanged.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $relationship
     * @param  mixed  $value
     * @param  \Closure(): mixed  $lookup
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function resolveChild(Builder $relationship, mixed $value, \Closure $lookup): ?Model
    {
        $child = $relationship instanceof Relation ? $relationship->getRelated() : $relationship->getModel();

        if (!in_array(ResolvesMeRouteBinding::class, class_uses_recursive($child), true)) {

            $found = $lookup();

            return $found instanceof Model ? $found : null;
        }

        $kind = self::kind($child);

        if ($value !== self::ME) {
            return $this->found($child, $kind, $lookup);
        }

        $own = $this->own($child, $kind);

        return WriteConnection::during($child, static fn (): bool => WriteConnection::query($relationship)->whereKey($own->getKey())->exists()) ? $own : null;
    }

    /**
     * The caller's own instance of the model's kind, when it is one of the
     * model's class.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $kind
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    private function own(Model $model, string $kind): Model
    {
        $caller = $this->callers->caller($this->request);

        $own = match ($kind) {
            self::SESSION  => $caller?->session,
            self::IDENTITY => $caller?->identity,
            default        => $caller?->principal,
        };

        if ($own instanceof $model) {
            return $own;
        }

        throw new AuthenticationException(ConsumerMessages::UNAUTHENTICATED, [$this->callers->guard($this->request)]);
    }

    /**
     * What the model's own lookup finds on the write connection, when the
     * request has a caller and it agrees with the caller's credential.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $kind
     * @param  \Closure(): mixed  $lookup
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Throwable
     */
    private function found(Model $model, string $kind, \Closure $lookup): ?Model
    {
        $caller = $this->callers->caller($this->request);

        if ($caller === null) {
            return null;
        }

        $found = WriteConnection::during($model, $lookup);

        return $found instanceof $model && $this->agrees($found, $kind, $caller) ? $found : null;
    }

    /**
     * Whether the instance found agrees with the caller's credential.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $found
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Authentication\Routing\Caller  $caller
     * @return bool
     *
     * @throws \Throwable
     */
    private function agrees(Model $found, string $kind, Caller $caller): bool
    {
        return match ($kind) {
            self::SESSION  => $found instanceof EloquentSession && $this->isCallersSession($found, $caller),
            self::IDENTITY => $found instanceof Identity        && self::isSameIdentity($found, $caller->identity),
            default        => $found instanceof Principal       && $this->isAddressable($found, $caller),
        };
    }

    /**
     * Whether the session is the caller's: owned by its identity and, for a
     * refresh or a pending credential, the very session the credential proves.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Routing\Caller  $caller
     * @return bool
     */
    private function isCallersSession(EloquentSession&Model $session, Caller $caller): bool
    {
        return SessionOwnership::isOwner($session, $caller->identity)
            && ($caller->credential === CallerCredential::ACCESS || self::isSameSession($session, $caller->session));
    }

    /**
     * Whether the caller may address the principal: its current principal, one
     * its pending session offers, or, for any other credential, one its
     * identity may use the application as.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Routing\Caller  $caller
     * @return bool
     *
     * @throws \Throwable
     */
    private function isAddressable(Principal $principal, Caller $caller): bool
    {
        if (self::isSamePrincipal($principal, $caller->principal)) {
            return true;
        }

        if ($caller->pending === null) {
            return self::isSamePrincipal($principal, $this->callers->admitted($caller, $principal));
        }

        $offered = array_filter($caller->pending->principals, static fn (Principal $candidate): bool => self::isSamePrincipal($principal, $candidate));

        return $offered !== [];
    }

    /**
     * The kind of instance the model binds.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     *
     * @throws \LogicException
     */
    private static function kind(Model $model): string
    {
        return match (true) {
            $model instanceof Session   => self::SESSION,
            $model instanceof Identity  => self::IDENTITY,
            $model instanceof Principal => self::PRINCIPAL,
            default                     => throw new \LogicException(sprintf('The me route binding binds a session, an identity or a principal; %s is none.', $model::class)),
        };
    }

    /**
     * Whether the two are the same session: the same class with the same
     * identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $other
     * @return bool
     */
    private static function isSameSession(Session $session, ?Session $other): bool
    {
        return $other !== null
            && $session::class === $other::class
            && IdentifierCoercion::matches($session->getSessionIdentifier(), $other->getSessionIdentifier());
    }

    /**
     * Whether the two are the same identity: the same class with the same
     * identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $other
     * @return bool
     */
    private static function isSameIdentity(Identity $identity, Identity $other): bool
    {
        return $identity::class === $other::class
            && IdentifierCoercion::matches($identity->getAuthIdentifier(), $other->getAuthIdentifier());
    }

    /**
     * Whether the two are the same principal: the same class with the same
     * principal identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $other
     * @return bool
     */
    private static function isSamePrincipal(Principal $principal, ?Principal $other): bool
    {
        return $other !== null
            && $principal::class === $other::class
            && IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $other->getPrincipalIdentifier());
    }
}
