<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The principals an identity may act as, judged for admission with their
 * tenants loaded together in one query per group.
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

        /** The identity that listed them, or `null` for the resolver's default. */
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
     * The one principal the resolver's default gives, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return self
     */
    public static function resolved(?Principal $principal): self
    {
        return new self([$principal], null);
    }

    /**
     * Why each of the listed principals may not hold a session of the guard's
     * application, in order, `null` for each that may.
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
     * The principal's stored copy when it is active, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private static function activeCopy(Principal $principal): ?Principal
    {
        return WriteConnection::stored($principal, static fn (Principal $stored): ?Principal => ActivationPolicy::isActive($stored) ? $stored : null);
    }

    /**
     * Why the principal may not hold a session of the guard's application,
     * judged on its stored copy with its loaded tenant.
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
     * Load each group's tenant relation on the write connection, keyed by each
     * principal's object id.
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
     * class, connection and relation.
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

            $group = $principal::class . '@' . $principal->getConnectionName() . '@' . $name;

            $groups[$group] ??= [$name, []];
            $groups[$group][1][] = $principal;
        }

        return $groups;
    }

    /**
     * Load the relation on the models together, reading alone any tenant the
     * load missed, keyed by each model's object id.
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

            if (self::isMissed($model, $name, $tenant)) {

                $alone = $model->withoutRelations();

                $alone->preventsLazyLoading = false;

                $tenant = $alone->getRelationValue($name);

                $model->setRelation($name, $tenant);
            }

            if ($tenant instanceof Model) {
                $tenant->preventsLazyLoading = false;
            }

            $loaded[spl_object_id($model)] = [$name, $tenant];
        }

        return $loaded;
    }

    /**
     * Whether the eager load found no tenant where the principal's own relation
     * may still name one.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $name
     * @param  mixed  $tenant
     * @return bool
     */
    private static function isMissed(Model $model, string $name, mixed $tenant): bool
    {
        if ($tenant instanceof Model ? $tenant->exists : $tenant !== null) {
            return false;
        }

        $relation = $model->newQueryWithoutRelationships()->getRelation($name);

        return !$relation instanceof MorphTo || ($model->getAttributes()[$relation->getMorphType()] ?? '') !== '';
    }

    /**
     * The tenant relation name of a principal model that uses
     * `ActsAsPrincipal`, or `null`.
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
