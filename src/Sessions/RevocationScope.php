<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
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
 * The sessions a bulk revocation ends, the "tokens valid after" cutoff that
 * ends its session-less access tokens, and any pending identifier changes.
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

        /** The keys of the identity's pending identifier changes that end with its sessions; none for a principal's scope. */
        public array $changes = [],
    ) {}

    /**
     * Every session of the identity, read on the write connection, and its
     * pending identifier changes of the types given.
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

        return new self($sessions, self::cutoffOf($identity), $identity, null, changes: $changes);
    }

    /**
     * Every session acting as the principal, read on the write connection, with
     * the tenant whose deactivation ends them when that is why.
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
            self::cutoffOf($principal),
            $owner,
            $principal,
            $tenant,
        );
    }

    /**
     * Every session acting in the tenant, of every guard and principal, read on
     * the write connection.
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
     * session-less access tokens keep working.
     *
     * @return self
     */
    public function keepingCutoff(): self
    {
        return new self($this->sessions, null, $this->identity, $this->principal, $this->tenant, $this->changes);
    }

    /**
     * The identity's or principal's "tokens valid after" holder, or `null` when
     * it records none or is an Eloquent model whose `exists` is `false`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal  $holder
     * @return ?\SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter
     */
    private static function cutoffOf(Identity|Principal $holder): ?HasTokensValidAfter
    {
        if (!$holder instanceof HasTokensValidAfter || ($holder instanceof Model && !$holder->exists)) {
            return null;
        }

        return $holder;
    }

    /**
     * The principal's owning identity, read through
     * `WriteConnection::stored()`, or `null` when it cannot be read.
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
