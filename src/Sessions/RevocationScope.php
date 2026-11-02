<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The sessions a bulk revocation ends: an identity's, a principal's, or those
 * acting in a tenant, pending sessions among them (a pending session is a
 * session row like any other, so its credential ends with it), the "tokens
 * valid after" cutoff that ends its access tokens issued without a session,
 * and, for an identity whose identifiers can be changed, its pending identifier
 * changes, which end with them.
 *
 * An identity's sessions are those its `sessions()` relation returns, of every
 * guard; a principal's are the configured session model's sessions that record
 * it as their principal. Only an identity that implements `HasSessions` can
 * hold a session (the session service refuses to start a session for any
 * other), so a scope whose identity does not (access-only mode, where the
 * package's tables may not exist) touches none and only moves its cutoff, and
 * an unsaved principal has none to find. A principal's scope ends no identifier
 * change: the identity that requested one keeps its other sessions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RevocationScope
{
    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?array{0: \Illuminate\Contracts\Database\Eloquent\Builder, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession}  $sessions
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter  $cutoff
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  list<string>  $changes
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function __construct(

        /** A query of the scope's sessions, in any state, with their model, or `null` when it has none to find. */
        public ?array $sessions,

        /** The scope's "tokens valid after" holder, when it records one. */
        public ?HasTokensValidAfter $cutoff,

        /** The identity whose sessions end, or the principal's owner, when known. */
        public ?Identity $identity,

        /** The principal whose sessions end, for a principal's scope. */
        public ?Principal $principal,

        /** The tenant whose deactivation ends them, if that is why. */
        public ?Tenant $tenant = null,

        /** The keys of the identity's pending identifier changes that end with its sessions (see `PendingChanges::key()`); none for a principal's scope. */
        public array $changes = [],
    ) {}

    /**
     * Every session of the identity, through its `sessions()` relation, read on
     * the write connection, and its pending identifier changes of the types
     * given, for an identity whose identifiers can be changed: a change link
     * needs no session, so one requested from a session that ends must end with
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  list<string>  $changeTypes
     * @return self
     *
     * @throws \LogicException
     */
    public static function identity(Identity $identity, array $changeTypes = []): self
    {
        $sessions = $identity instanceof HasSessions ? IdentitySessions::query($identity) : null;
        $changes  = array_map(static fn (string $type): string => PendingChanges::key($identity, $type), $changeTypes);

        return new self($sessions, $identity instanceof HasTokensValidAfter ? $identity : null, $identity, null, changes: $changes);
    }

    /**
     * Every session acting as the principal, of the configured session model,
     * read on the write connection, with the tenant whose deactivation ends
     * them when that is why, and the principal's owning identity, read afresh
     * on the write connection (a 2D principal is its own). When that identity
     * does not implement `HasSessions`, the principal can have no session, so
     * none is looked for; when the owner cannot be read, they are.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return self
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function principal(Principal $principal, ?Tenant $tenant = null): self
    {
        $owner    = self::ownerOf($principal);
        $id       = PrincipalReference::id($principal);
        $sessions = null;

        if ($id !== null && ($owner === null || $owner instanceof HasSessions)) {

            $model = SessionLookup::model();

            [$type, $key] = PrincipalReference::columns($model);

            $sessions = [WriteConnection::query($model->newQuery())->where([$type => PrincipalReference::type($principal), $key => $id]), $model];
        }

        return new self(
            $sessions,
            $principal instanceof HasTokensValidAfter ? $principal : null,
            $owner,
            $principal,
            $tenant,
        );
    }

    /**
     * Every session acting in the tenant (whose active tenant it is), of the
     * configured session model, of every guard, read on the write connection
     * through the session table's tenant index, whatever principal it acts as:
     * a principal of another tenant may act in this one, and pending sessions
     * recording the tenant end with the rest. It has no cutoff and no identity
     * or principal of its own: a token without a session acts only in its
     * principal's own tenant, which the principals' scopes end.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return self
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function activeTenant(Tenant $tenant): self
    {
        $id = IdentifierCoercion::stringify($tenant->getTenantIdentifier());

        if ($id === null) {
            return new self(null, null, null, null, $tenant);
        }

        $model = SessionLookup::model();

        return new self([WriteConnection::query($model->newQuery())->where($model->qualifyColumn($model->getTenantIdName()), $id), $model], null, null, null, $tenant);
    }

    /**
     * The same sessions with the cutoff left where it is, so the scope's
     * session-less access tokens keep working: how the request's own
     * session-less token is kept when its identity signs out everywhere else.
     *
     * @return self
     */
    public function keepingCutoff(): self
    {
        return new self($this->sessions, null, $this->identity, $this->principal, $this->tenant, $this->changes);
    }

    /**
     * The principal's owning identity, read through `WriteConnection::stored()`
     * so a relation set by whoever loaded it cannot stand in for the stored
     * owner, or `null` when it cannot be read: a `LogicException`, as
     * `ActsAsPrincipal` throws for a deleted owner.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function ownerOf(Principal $principal): ?Identity
    {
        if ($principal instanceof Identity) {
            return $principal;
        }

        try {
            return WriteConnection::stored($principal, static fn (Principal $stored): Identity => $stored->getIdentity());
        } catch (\LogicException) {
            return null;
        }
    }
}
