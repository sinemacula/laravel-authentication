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
 * Every live session whose active tenant is the tenant (unrevoked and before
 * both its deadlines), on every guard, pending ones included, is read on the
 * write connection in key order, a chunk at a time, each chunk with a locking
 * read, in one transaction on the session model's connection (a savepoint
 * inside a caller's transaction there, so it commits or rolls back with the
 * caller's own work). Each session is judged against the policy as it answers
 * for that session's application, identity and principal: a session recorded at
 * the very version answered, neither `null`, is skipped; an active one that
 * falls short is revoked (`tenant_policy_changed`) and one that meets it
 * records the version; a pending one is revoked only when it would need another
 * connection, since its activation judges a further factor itself. A session
 * whose owner or principal no longer loads is revoked when active. Each
 * revocation is one conditional update on the session still being active in the
 * tenant and unrevoked, and is reported with `SessionRevoked` once committed.
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
            $after   = null;

            do {
                $chunk = $this->chunk($model, $tenantId, $after, $now);

                foreach ($chunk as $session) {
                    $revoked += $this->revokeIfShort($session, $tenant, $tenantId, $now) ? 1 : 0;
                    $after = $session->getKey();
                }
            } while (count($chunk) === self::CHUNK);

            return $revoked;
        });
    }

    /**
     * The next chunk of the tenant's live sessions after the key given, in key
     * order, read with a locking read on the write connection: unrevoked, and
     * before both deadlines at `$now`, so a session that has already ended
     * (waiting to be pruned) is neither judged, revoked nor counted.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  string  $tenantId
     * @param  mixed  $after
     * @param  \Carbon\CarbonImmutable  $now
     * @return list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>
     */
    private function chunk(EloquentSession&Model $model, string $tenantId, mixed $after, CarbonImmutable $now): array
    {
        $at       = $model->fromDateTime($now);
        $absolute = $model->getAbsoluteExpiresAtName();

        $query = WriteConnection::query($model->newQuery())
            ->where($model->getTenantIdName(), $tenantId)
            ->whereNull($model->getRevokedAtName())
            ->where($model->getIdleExpiresAtName(), '>', $at)
            ->where(static function ($query) use ($absolute, $at): void {
                $query->whereNull($absolute)->orWhere($absolute, '>', $at);
            })
            ->when($after !== null, static fn ($query) => $query->where($model->getKeyName(), '>', $after))
            ->orderBy($model->getKeyName())
            ->limit(self::CHUNK)
            ->lockForUpdate();

        /** @var list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> */
        return array_values(WriteConnection::during($model, static fn (): array => $query->get()->all()));
    }

    /**
     * Judge one session against the policy and act on the verdict: revoke it
     * when it falls short, or record the version it meets; returns whether it
     * was revoked.
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
     * The session judged against the policy as it answers for the session's
     * application, identity and principal, or `null` when the session is
     * recorded at the very version answered (neither `null`) and so is skipped.
     * A session whose owner or principal no longer loads lacks what the policy
     * is asked about, and is judged as falling short of it.
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

        $guard       = (string) $session->getGuard();
        $recorded    = $session->getTenantPolicyVersion();
        $requirement = TenantPolicyCheck::requirementFor($guard, $identity, $principal, $tenant, $session);

        return $recorded !== null && $recorded === $requirement->version
            ? null
            : TenantPolicyCheck::judge($requirement, $tenant, $guard, $identity, $session, $now, null);
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
     * the tenant and unrevoked, and report it once committed; returns whether
     * this call revoked it.
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
