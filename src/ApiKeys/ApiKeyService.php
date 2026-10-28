<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\Expression;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Scopes\Scopes;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;

/**
 * A guard's API keys, `Auth::apiKeys($guard)`: issue a key to a non-human
 * identity for one of its principals, rotate it with a bounded overlap, revoke
 * it, and list what may be shown about a principal's keys.
 *
 * The guard is the one audience a key authenticates for: an `api_key` guard,
 * whose requests present the key, or a `jwt` guard, whose client credentials
 * exchange takes the key's public part and secret as an OAuth client's id and
 * secret. Every keyed operation names the principal the key must belong to,
 * matched by type and identifier in the statement itself, and a key of another
 * principal or guard is treated as absent. Managing keys is privileged: the
 * application authorises its caller to manage the principal's keys first; this
 * package decides no permission.
 *
 * Issuing and rotating are trusted, programmatic actions, so a principal the
 * identity does not act as, one the guard's audience does not admit, a
 * malformed or rejected scope, a past expiry or an overlap out of range is an
 * `InvalidArgumentException` (`InvalidScopeException` for scopes) rather than a
 * failed authentication. Each write is one conditional statement on the key's
 * own connection, and its event is dispatched once it is committed there.
 *
 * Holds the guard and reads its provider, resolver, dispatcher and request each
 * time it runs, so it keeps nothing between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeyService
{
    /** @var int Public parts drawn before giving up on a unique one. */
    private const int ISSUE_ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  ?\Closure(string): string  $publicParts
     */
    public function __construct(

        /** The guard whose keys these are. */
        private AbstractGuard $guard,

        /** Container the audience policy, the scope registry and the transactions manager are resolved from. */
        private Container $container,

        /** Draws a new public part under a prefix; the package's secure generator unless given. */
        private ?\Closure $publicParts = null,
    ) {}

    /**
     * Issue a key to the non-human identity, acting as the principal, granting
     * the scopes, optionally named and expiring. The principal must be one the
     * identity acts as on the guard, and admitted by the guard's audience; the
     * key records it, the identity and the principal's tenant, which must be
     * loadable, and authenticates only as them. `ApiKeyIssued` follows once
     * committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\MachineIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  array<array-key, mixed>  $scopes
     * @param  ?string  $name
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @return \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function issue(MachineIdentity $identity, Principal $principal, array $scopes = [], ?string $name = null, ?CarbonInterface $expiresAt = null): IssuedApiKey
    {
        $now       = CarbonImmutable::now()->startOfSecond();
        $principal = $this->actingPrincipal($identity, $principal);
        $granted   = Scopes::grantable($this->scopeRegistry(), $this->guard->getName(), $principal, $scopes);
        $tenant    = WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());

        [$key, $issued] = $this->insert([
            'guard'                => $this->guard->getName(),
            'name'                 => ApiKeyRules::name($name),
            'authenticatable_type' => CredentialBinding::ownerType($identity),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getAuthIdentifier()),
            'principal_type'       => PrincipalReference::type($principal),
            'principal_id'         => PrincipalReference::id($principal),
            'tenant_id'            => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
            'scopes'               => $granted,
            'expires_at'           => ApiKeyRules::expiry($expiresAt, $now),
        ], $now);

        $this->report($key, new ApiKeyIssued($this->context($key, $identity, $principal, $tenant)));

        return $issued;
    }

    /**
     * Rotate the principal's live key: issue its replacement, with the same
     * guard, owner, principal, tenant, name and scopes (held to the scope
     * registry again) and the given expiry (none by default), and end the
     * replaced key once the overlap passes, or at its own expiry when that
     * comes sooner. Both keys authenticate during the overlap. `null` when the
     * principal has no such key on the guard, or it is revoked, expired or
     * already rotated. `ApiKeyRotated` follows once committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $keyId
     * @param  ?int  $overlapSeconds
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @return ?\SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     * @throws \Throwable
     */
    public function rotate(Principal $principal, string $keyId, ?int $overlapSeconds = null, ?CarbonInterface $expiresAt = null): ?IssuedApiKey
    {
        $now      = CarbonImmutable::now()->startOfSecond();
        $deadline = $now->addSeconds(ApiKeyRules::overlap($overlapSeconds));
        $expiry   = ApiKeyRules::expiry($expiresAt, $now);
        $previous = $this->owned($principal, $keyId)?->first();

        if ($previous === null || ApiKeyLookup::refusal($previous, $this->guard->getName(), $now) !== null || $previous->rotated_at !== null) {
            return null;
        }

        $granted = Scopes::grantable($this->scopeRegistry(), $this->guard->getName(), $principal, $previous->scopes);
        $rotated = $previous->getConnection()->transaction(fn (): ?array => $this->replace($previous, $deadline, $now, [
            'guard'                => $previous->guard,
            'name'                 => $previous->name,
            'authenticatable_type' => $previous->authenticatable_type,
            'authenticatable_id'   => $previous->authenticatable_id,
            'principal_type'       => $previous->principal_type,
            'principal_id'         => $previous->principal_id,
            'tenant_id'            => $previous->tenant_id,
            'scopes'               => $granted,
            'expires_at'           => $expiry,
        ]));

        if ($rotated === null) {
            return null;
        }

        [$key, $issued] = $rotated;

        $this->report($key, new ApiKeyRotated($this->context($key, $this->owner($key), $principal, self::tenantOf($principal)), $previous->id));

        return $issued;
    }

    /**
     * Revoke the principal's key: it stops authenticating at once, as does
     * every access token a client credentials exchange issued from it. Whether
     * this call revoked it: `false` when the principal has no such key on the
     * guard or it was already revoked. `ApiKeyRevoked` follows once committed,
     * only from the call that revoked it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $keyId
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public function revoke(Principal $principal, string $keyId): bool
    {
        $now   = CarbonImmutable::now()->startOfSecond();
        $owned = $this->owned($principal, $keyId);
        $key   = $owned?->clone()->first();

        if ($owned === null || $key === null) {
            return false;
        }

        $at      = $key->fromDateTime($now);
        $revoked = $owned->toBase()->whereNull('revoked_at')->update(['revoked_at' => $at, 'updated_at' => $at]);

        if ($revoked === 0) {
            return false;
        }

        $this->report($key, new ApiKeyRevoked($this->context($key, $this->owner($key), $principal, self::tenantOf($principal))));

        return true;
    }

    /**
     * What may be shown about the principal's key on the guard, or `null` when
     * it has no such key.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $keyId
     * @return ?\SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary
     */
    public function find(Principal $principal, string $keyId): ?ApiKeySummary
    {
        $key = $this->owned($principal, $keyId)?->first();

        return $key === null ? null : ApiKeySummary::of($key);
    }

    /**
     * What may be shown about each of the principal's keys on the guard,
     * revoked, expired and rotated ones included, newest first.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return list<\SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary>
     */
    public function keys(Principal $principal): array
    {
        $id = PrincipalReference::id($principal);

        if ($id === null) {
            return [];
        }

        /** @var list<\SineMacula\Laravel\Authentication\Models\ApiKey> $keys */
        $keys = $this->ofPrincipal(PrincipalReference::type($principal), $id)->orderByDesc('created_at')->orderByDesc('id')->get()->all();

        return array_map(ApiKeySummary::of(...), $keys);
    }

    /**
     * Replace the previous key inside the rotation's transaction: end it at the
     * deadline, or at its own expiry when sooner, in one conditional statement
     * that only a live, unrotated key matches, then insert its replacement.
     * `null` when another rotation, a revocation or its expiry got there first.
     *
     * An explicit `CASE` sets the new expiry, since `LEAST()` over a key that
     * never expires is `NULL` on some engines, which would leave it valid
     * forever.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $previous
     * @param  \Carbon\CarbonImmutable  $deadline
     * @param  \Carbon\CarbonImmutable  $now
     * @param  array<string, mixed>  $row
     * @return ?array{0: \SineMacula\Laravel\Authentication\Models\ApiKey, 1: \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function replace(ApiKey $previous, CarbonImmutable $deadline, CarbonImmutable $now, array $row): ?array
    {
        $id         = (string) Str::uuid();
        $connection = $previous->getConnection();
        $column     = $connection->getQueryGrammar()->wrap('expires_at');
        $ends       = $connection->getPdo()->quote((string) $previous->fromDateTime($deadline));
        $at         = $previous->fromDateTime($now);

        $replaced = $previous->newQuery()
            ->toBase()
            ->where('id', $previous->id)
            ->where('guard', $previous->guard)
            ->where('principal_type', $previous->principal_type)
            ->where('principal_id', $previous->principal_id)
            ->whereNull('revoked_at')
            ->whereNull('rotated_at')
            ->where(static fn (QueryBuilder $query): QueryBuilder => $query->whereNull('expires_at')->orWhere('expires_at', '>', $at))
            ->update([
                'expires_at'  => new Expression("CASE WHEN {$column} IS NULL OR {$column} > {$ends} THEN {$ends} ELSE {$column} END"),
                'rotated_at'  => $at,
                'replaced_by' => $id,
                'updated_at'  => $at,
            ]);

        return $replaced === 0 ? null : $this->insert($row, $now, $id);
    }

    /**
     * Insert a key from its row with a new public part and secret, drawing a
     * new public part while one collides with a stored key's, and return the
     * model the row holds and the issued key.
     *
     * @param  array<string, mixed>  $row
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $id
     * @return array{0: \SineMacula\Laravel\Authentication\Models\ApiKey, 1: \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function insert(array $row, CarbonImmutable $now, ?string $id = null): array
    {
        $prefix = ApiKeySettings::prefix();
        $secret = ApiKeyToken::newSecret();
        $key    = new ApiKey;

        $key->forceFill($row + [
            'id'          => $id ?? (string) Str::uuid(),
            'secret_hash' => ApiKeyToken::digest($secret),
            'created_at'  => $now,
            'updated_at'  => $now,
        ]);

        for ($attempt = 1; $attempt <= self::ISSUE_ATTEMPTS; $attempt++) {

            $key->forceFill(['prefix' => ($this->publicParts ?? ApiKeyToken::newPublicPart(...))($prefix)]);

            if ($key->newQuery()->toBase()->insertOrIgnore($key->getAttributes()) === 1) {

                $stored = $key->newFromBuilder($key->getAttributes());

                return [$stored, new IssuedApiKey($stored->id, ApiKeyToken::join($stored->prefix, $secret), ApiKeySummary::of($stored))];
            }
        }

        self::collided();
    }

    /**
     * Give up issuing a key whose public parts kept colliding with stored
     * keys', which a secure generator makes practically impossible.
     *
     * @return never
     *
     * @throws \UnexpectedValueException
     */
    private static function collided(): never
    {
        throw new \UnexpectedValueException(sprintf('Could not draw an API key public part that no stored key has in %d attempts.', self::ISSUE_ATTEMPTS));
    }

    /**
     * The principal, as the guard's resolver returns it for the identity, that
     * the guard's audience admits; a key may only be issued for that.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\MachineIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function actingPrincipal(MachineIdentity $identity, Principal $principal): Principal
    {
        $name     = $this->guard->getName();
        $resolved = PinnedPrincipal::resolve($this->guard->getPrincipalResolver(), $identity, $principal);

        /** @var \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy $audience */
        $audience = $this->container->make(AudiencePolicy::class);

        return ApiKeyRules::principal($name, $resolved, $resolved === null ? null : $audience->admit($name, $identity, $resolved, null));
    }

    /**
     * The guard's keys of the principal, by its recorded type and identifier,
     * read on the write connection.
     *
     * @param  string  $type
     * @param  string  $id
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\ApiKey>
     */
    private function ofPrincipal(string $type, string $id): Builder
    {
        return WriteConnection::query((new ApiKey)->newQuery())
            ->where('guard', $this->guard->getName())
            ->where('principal_type', $type)
            ->where('principal_id', $id);
    }

    /**
     * The query for the principal's key with the id on the guard, or `null`
     * when the id cannot name a key (not a UUID) or the principal has no
     * identifier, so neither costs a query.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $keyId
     * @return ?\Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\ApiKey>
     */
    private function owned(Principal $principal, string $keyId): ?Builder
    {
        $id = PrincipalReference::id($principal);

        return $id === null || !Str::isUuid($keyId) ? null : $this->ofPrincipal(PrincipalReference::type($principal), $id)->where('id', $keyId);
    }

    /**
     * The key's owner, reloaded through the guard's provider when it is still
     * the very identity the key records, for the events about it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function owner(ApiKey $key): ?Identity
    {
        $identity = $this->guard->getProvider()->retrieveById($key->authenticatable_id);

        return $identity instanceof Identity && CredentialBinding::isOwnedBy($key, $identity) ? $identity : null;
    }

    /**
     * The context of an event about the key.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function context(ApiKey $key, ?Identity $identity, Principal $principal, ?Tenant $tenant): EventContext
    {
        $client = ClientContext::fromRequest($this->guard->getRequest());

        return new EventContext($key->guard, $client, $identity, $principal, $tenant, credentialId: $key->id, scopes: $key->scopes);
    }

    /**
     * Dispatch the event once the key's writes are committed on its own
     * connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return void
     */
    private function report(ApiKey $key, AuthenticationEvent $event): void
    {
        $container  = $this->container;
        $dispatcher = $this->guard->getDispatcher();

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($key, static function () use ($dispatcher, $event): void {
                $dispatcher->dispatch($event);
            });
    }

    /**
     * The bound scope registry.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ScopeRegistry
     */
    private function scopeRegistry(): ScopeRegistry
    {
        /** @var \SineMacula\Laravel\Authentication\Contracts\ScopeRegistry */
        return $this->container->make(ScopeRegistry::class);
    }

    /**
     * The tenant the principal acts within, read on the write connection, or
     * `null` when it names none or the tenant cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \LogicException
     */
    private static function tenantOf(Principal $principal): ?Tenant
    {
        try {
            return WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
        } catch (TenantUnavailableException) {
            return null;
        }
    }
}
