<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The principals an identity may act as, listed for admission (a sign-in, a
 * pending session, a choice or switch screen), and the judging of those listed,
 * with each judged principal's tenant read once for the lot.
 *
 * An identity's `principals()` hydrates its rows together, so Eloquent's strict
 * mode forbids each of them a lazy load, and reading each principal's tenant on
 * its own would be one query per principal. So once the listed principals' own
 * activity is judged, the tenant relation of each active one that uses
 * `ActsAsPrincipal` (the relation its `getTenantRelationName()` names, when
 * that is a relation of the model) is loaded on them together, on the write
 * connection, after their own query: one query per principal class (one per
 * tenant type for a polymorphic relation, and those of the tenant model's own
 * `$with`), however many principals there are. No global scope or eager load
 * the application put on `principals()` can constrain it, and whatever was
 * loaded under that name, nested relations included, is replaced, so each
 * principal holds the very tenant a lazy load would read. The tenants loaded
 * allow lazy loading, as a tenant read on its own does, while the principals
 * keep the strictness their query gave them. An inactive principal is refused
 * without its tenant being read. A principal that implements `getTenant()`
 * itself has no relation the package can know, and is read as it always was.
 *
 * Each principal is still judged as it is stored (`WriteConnection::stored()`),
 * with only the tenant loaded here carried onto the copy; a principal the
 * resolver supplied carries nothing, since a relation it set cannot vouch for
 * the principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrincipalListing
{
    /**
     * Constructor.
     *
     * @param  array<array-key, mixed>  $candidates
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     */
    private function __construct(

        /** The principals listed, before any check. */
        public array $candidates,

        /** The identity whose `principals()` listed them, or `null` for the resolver's default. */
        private ?Identity $identity,
    ) {}

    /**
     * The identity's `principals()`, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return self
     */
    public static function of(HasPrincipals&Identity $identity): self
    {
        $candidates = WriteConnection::during($identity, static fn (): array => WriteConnection::query($identity->principals())->get()->all());

        return new self($candidates, $identity);
    }

    /**
     * The one principal the resolver's default gives, or none, for an identity
     * that is its own principal or lists none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return self
     */
    public static function resolved(?Principal $principal): self
    {
        return new self([$principal], null);
    }

    /**
     * Why each of the principals, taken from this listing, may not hold a
     * session of the guard's application (`PrincipalAdmission::refusal()`), in
     * their order, `null` for each that may: judged as stored, the tenants of
     * those that are active loaded together on the write connection before any
     * tenant is judged. An inactive principal is refused without its tenant
     * being read, as when each was judged alone.
     *
     * @param  string  $guard
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return list<?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function refusals(string $guard, array $principals): array
    {
        $stored = array_map(static fn (Principal $principal): ?Principal => self::activeCopy($principal), $principals);
        $active = array_filter($principals, static fn (int $index): bool => $stored[$index] !== null, ARRAY_FILTER_USE_KEY);
        $loaded = $this->identity === null ? [] : self::loadTenants($this->identity, $active);

        return array_map(
            static fn (Principal $principal, ?Principal $copy): ?FailureReason => self::refusal($guard, $copy, $loaded[spl_object_id($principal)] ?? null),
            $principals,
            $stored,
        );
    }

    /**
     * The principal's stored copy (`WriteConnection::stored()`) when it is
     * active, or `null` when it is not.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private static function activeCopy(Principal $principal): ?Principal
    {
        return WriteConnection::stored($principal, static fn (Principal $stored): ?Principal => ActivationPolicy::isActive($stored) ? $stored : null);
    }

    /**
     * Why the principal may not hold a session of the guard's application:
     * `principal_inactive` when it has no active stored copy, otherwise judged
     * on that copy with the tenant relation loaded for it, if any, set on it.
     *
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $stored
     * @param  ?array{0: string, 1: mixed}  $tenant
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function refusal(string $guard, ?Principal $stored, ?array $tenant): ?FailureReason
    {
        if ($stored === null) {
            return FailureReason::PRINCIPAL_INACTIVE;
        }

        if ($tenant !== null) {

            assert($stored instanceof Model);

            $stored->setRelation(...$tenant);
        }

        return PrincipalAdmission::refusalOfActive($guard, $stored);
    }

    /**
     * Load the tenant relation of each principal model that uses
     * `ActsAsPrincipal`, together for each principal class and relation (one
     * query, or one per tenant type for a polymorphic relation), inside
     * `WriteConnection::during()` for the identity, and return the relation
     * name and what it loaded for each, by the principal's object id.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<int, \SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return array<int, array{0: string, 1: mixed}>
     */
    private static function loadTenants(Identity $identity, array $principals): array
    {
        $groups = self::groups($principals);

        return WriteConnection::during($identity, static function () use ($groups): array {

            $loaded = [];

            foreach ($groups as [$name, $models]) {
                $loaded += self::load($name, $models);
            }

            return $loaded;
        });
    }

    /**
     * The principal models whose tenant relation the package knows, grouped by
     * class and relation, each group with the relation's name.
     *
     * @param  array<int, \SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return array<string, array{0: string, 1: list<\Illuminate\Database\Eloquent\Model>}>
     */
    private static function groups(array $principals): array
    {
        $groups = [];

        foreach ($principals as $principal) {

            $name = $principal instanceof Model ? self::tenantRelation($principal) : null;

            if ($name === null) {
                continue;
            }

            $group = $principal::class . '@' . $name;

            $groups[$group] ??= [$name, []];
            $groups[$group][1][] = $principal;
        }

        return $groups;
    }

    /**
     * Load the relation on the models together, let the tenants it loads
     * lazy-load as a tenant read on its own may, and return the relation name
     * and what it loaded for each model, by the model's object id.
     *
     * @param  string  $name
     * @param  list<\Illuminate\Database\Eloquent\Model>  $models
     * @return array<int, array{0: string, 1: mixed}>
     */
    private static function load(string $name, array $models): array
    {
        (new EloquentCollection($models))->load($name);

        $loaded = [];

        foreach ($models as $model) {

            $tenant = $model->getRelation($name);

            if ($tenant instanceof Model) {
                $tenant->preventsLazyLoading = false;
            }

            $loaded[spl_object_id($model)] = [$name, $tenant];
        }

        return $loaded;
    }

    /**
     * The tenant relation of a principal model that uses `ActsAsPrincipal`: the
     * name its protected `getTenantRelationName()` gives, when that is a
     * relation of the model; otherwise `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $principal
     * @return ?string
     */
    private static function tenantRelation(Model $principal): ?string
    {
        if (!in_array(ActsAsPrincipal::class, class_uses_recursive($principal), true)) {
            return null;
        }

        $name = (new \ReflectionMethod($principal, 'getTenantRelationName'))->invoke($principal);

        assert(is_string($name));

        return $principal->isRelation($name) ? $name : null;
    }
}
