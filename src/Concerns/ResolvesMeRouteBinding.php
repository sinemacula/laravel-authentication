<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Routing\MeBinding;

/**
 * The `me` route binding, for an application's session, identity and principal
 * models: a route parameter of `me` binds the caller's own instance, from
 * whichever credential the route reads (the access credential of its guard, or
 * the refresh or pending one it declares with `authentication.refresh` or
 * `authentication.pending:<action>`), and a request without one is a `401`. Any
 * other value goes to Eloquent's own lookup, so custom keys, soft deletes and
 * scoped bindings keep working, read on the write connection and scoped to the
 * caller: what it finds must agree with the credential (the caller's identity,
 * a session of it, the very session a refresh or pending credential proves, or
 * a principal the caller may address) or the binding misses, which Laravel
 * answers with a `404`.
 *
 * Opt-in: the shipped session model does not use it. The trait reserves `me` as
 * a value of every parameter the model binds, and binds only the caller's own
 * instances, so a route that must bind another identity's (an administrator's)
 * binds through `Route::bind()` or a model without it. A scoped child binding
 * reaches the trait only through its parent, so both models of one use it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait ResolvesMeRouteBinding
{
    /**
     * Retrieve the model for a bound value: the caller's own instance for `me`,
     * otherwise Eloquent's lookup when it agrees with the caller.
     *
     * @param  mixed  $value
     * @param  mixed  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        return MeBinding::current()->resolve($this, $value, fn (): mixed => parent::resolveRouteBinding($value, $field));
    }

    /**
     * Retrieve the model for a bound value, soft-deleted ones included: the
     * caller's own instance for `me`, otherwise Eloquent's lookup when it
     * agrees with the caller.
     *
     * @param  mixed  $value
     * @param  mixed  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function resolveSoftDeletableRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        return MeBinding::current()->resolve($this, $value, fn (): mixed => parent::resolveSoftDeletableRouteBinding($value, $field));
    }

    /**
     * Retrieve the child model for a bound value through the relationship the
     * child type names: as a top-level binding within it when the child's model
     * uses this trait, otherwise Eloquent's lookup unchanged.
     *
     * @param  mixed  $childType
     * @param  mixed  $value
     * @param  mixed  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function resolveChildRouteBinding(mixed $childType, mixed $value, mixed $field): ?Model
    {
        return MeBinding::current()->resolveChild(
            $this->{$this->childRouteBindingRelationshipName($childType)}(),
            $value,
            fn (): mixed => parent::resolveChildRouteBinding($childType, $value, $field),
        );
    }

    /**
     * Retrieve the child model for a bound value through the relationship the
     * child type names, soft-deleted ones included: as a top-level binding
     * within it when the child's model uses this trait, otherwise Eloquent's
     * lookup unchanged.
     *
     * @param  mixed  $childType
     * @param  mixed  $value
     * @param  mixed  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function resolveSoftDeletableChildRouteBinding(mixed $childType, mixed $value, mixed $field): ?Model
    {
        return MeBinding::current()->resolveChild(
            $this->{$this->childRouteBindingRelationshipName($childType)}(),
            $value,
            fn (): mixed => parent::resolveSoftDeletableChildRouteBinding($childType, $value, $field),
        );
    }
}
