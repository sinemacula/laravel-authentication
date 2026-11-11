<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;

/**
 * Applies a change of a tenant's authentication policy to the sessions active
 * in the tenant, at once and outside any request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantPolicyChanges
{
    /** @var int How many sessions one locking read takes. */
    public const int CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard applying the change; its client is the events'. */
        private GuardContext $context,

        /** Defers the reports until the revocations commit. */
        private AfterCommit $afterCommit,
    ) {}

    /**
     * Apply the tenant's changed policy to its sessions, returning how many
     * were revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \Throwable
     */
    public function apply(Tenant $tenant, CarbonImmutable $now): int
    {
        $tenantId = IdentifierCoercion::stringify($tenant->getTenantIdentifier());
        $model    = SessionLookup::model();

        if ($tenantId === null) {
            return 0;
        }

        return $model->getConnection()->transaction(function () use ($model, $tenant, $tenantId, $now): int {

            $revoked = 0;

            foreach (array_chunk(self::keys($model, $tenantId, $now), self::CHUNK) as $keys) {
                foreach (self::locked($model, $keys) as $session) {
                    $revoked += $this->revokeIfShort($session, $tenant, $tenantId, $now) ? 1 : 0;
                }
            }

            return $revoked;
        });
    }

    /**
     * The keys of the tenant's live sessions, in key order, read a chunk at a
     * time with a locking read on the write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  string  $tenantId
     * @param  \Carbon\CarbonImmutable  $now
     * @return list<mixed>
     */
    private static function keys(EloquentSession&Model $model, string $tenantId, CarbonImmutable $now): array
    {
        $at       = $model->fromDateTime($now);
        $absolute = $model->getAbsoluteExpiresAtName();
        $name     = $model->getKeyName();
        $keys     = [];
        $after    = null;

        do {
            $query = WriteConnection::query($model->newQuery())
                ->where($model->getTenantIdName(), $tenantId)
                ->whereNull($model->getRevokedAtName())
                ->where($model->getIdleExpiresAtName(), '>', $at)
                ->where(static function ($query) use ($absolute, $at): void {
                    $query->whereNull($absolute)->orWhere($absolute, '>', $at);
                })
                ->when($after !== null, static fn ($query) => $query->where($name, '>', $after))
                ->orderBy($name)
                ->limit(self::CHUNK)
                ->lockForUpdate();

            $chunk = WriteConnection::during($model, static fn (): array => $query->toBase()->pluck($name)->values()->all());
            array_push($keys, ...$chunk);
            $after = $chunk[count($chunk) - 1] ?? null;
        } while (count($chunk) === self::CHUNK);

        return $keys;
    }

    /**
     * The sessions under the keys given, read again with a locking read so each
     * is read as committed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  list<mixed>  $keys
     * @return list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>
     */
    private static function locked(EloquentSession&Model $model, array $keys): array
    {
        $query = WriteConnection::query($model->newQuery())
            ->whereIn($model->getKeyName(), $keys)
            ->orderBy($model->getKeyName())
            ->lockForUpdate();

        /** @var list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> */
        return array_values(WriteConnection::during($model, static fn (): array => $query->get()->all()));
    }

    /**
     * Judge one session against the policy and revoke it when it falls short,
     * or record the version it meets; whether it was revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $tenantId
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    private function revokeIfShort(EloquentSession&Model $session, Tenant $tenant, string $tenantId, CarbonImmutable $now): bool
    {
        $verdict = $this->verdictOf($session, $tenant, $now);

        if ($verdict === null) {
            return false;
        }

        $pending = $session->getStatus() === SessionStatus::PENDING;
        $short   = $verdict->standing    === TenantPolicyStanding::SSO_REQUIRED || (!$pending && !$verdict->isMet());

        if ($short) {
            return $this->revoke($session, $tenant, $tenantId, $now);
        }

        if (!$pending) {
            $this->record($session, $tenantId, $verdict->version);
        }

        return false;
    }

    /**
     * The session judged against the policy, or `null` when it is recorded at
     * the very version answered.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function verdictOf(EloquentSession&Model $session, Tenant $tenant, CarbonImmutable $now): ?TenantPolicyVerdict
    {
        $actors = self::actors($session);

        if ($actors === null) {
            return new TenantPolicyVerdict(TenantPolicyStanding::FACTOR_REQUIRED, null);
        }

        [$identity, $principal] = $actors;

        $recorded = $session->getTenantPolicyVersion();
        $source   = new ProofSource(current: true);
        $context  = TenantPolicyCheck::contextFor((string) $session->getGuard(), $identity, $principal, $tenant, $session, $source);

        try {
            $requirement = TenantPolicyCheck::requirementFor($context);

            return $recorded !== null && $recorded === $requirement->version
                ? null
                : TenantPolicyCheck::judge($requirement, $context, $now, $source);
        } finally {
            $context->expire();
        }
    }

    /**
     * The identity and principal the session records, loaded on the write
     * connection, or `null` when either no longer loads.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}
     */
    private static function actors(EloquentSession&Model $session): ?array
    {
        [$identity, $principal] = WriteConnection::during($session, static fn (): array => [$session->authenticatable()->first(), $session->principal()->first()]);

        return $identity instanceof Identity && $principal instanceof Principal ? [$identity, $principal] : null;
    }

    /**
     * Revoke the session as `tenant_policy_changed` while it is still active in
     * the tenant and unrevoked; whether this call revoked it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $tenantId
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    private function revoke(EloquentSession&Model $session, Tenant $tenant, string $tenantId, CarbonImmutable $now): bool
    {
        $reason  = RevocationReason::TENANT_POLICY_CHANGED;
        $revoked = RefreshRotationStore::revocation($session, $reason, $now);

        if (!$this->update($session, $tenantId, $revoked)) {
            return false;
        }

        $context = new EventContext($session->getGuard(), $this->context->client(), tenant: $tenant, session: $session, method: $session->getSignInMethod(), fromSession: true);
        $event   = new SessionRevoked($context, $reason);

        $this->afterCommit->run($session, fn () => $this->context->dispatch($event));

        return true;
    }

    /**
     * Record the version the session was found to meet, when it differs from
     * the one it records.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $tenantId
     * @param  ?string  $version
     * @return void
     */
    private function record(EloquentSession&Model $session, string $tenantId, ?string $version): void
    {
        if ($session->getTenantPolicyVersion() === $version) {
            return;
        }

        $this->update($session, $tenantId, [$session->getTenantPolicyVersionName() => $version]);
    }

    /**
     * Write the values on the session while it is still active in the tenant
     * and unrevoked, mirroring them on the model; returns whether it did.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $tenantId
     * @param  array<string, mixed>  $values
     * @return bool
     *
     * @imperative
     */
    private function update(EloquentSession&Model $session, string $tenantId, array $values): bool
    {
        $affected = $session->getConnection()
            ->table($session->getTable())
            ->where($session->getKeyName(), $session->getKey())
            ->where($session->getTenantIdName(), $tenantId)
            ->whereNull($session->getRevokedAtName())
            ->update($values);

        if ($affected !== 1) {
            return false;
        }

        PendingState::mirror($session, $values);

        return true;
    }
}
