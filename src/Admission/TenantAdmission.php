<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Which tenant a principal acts in, and whether it may.
 *
 * Interim: the access contracts are built alongside, and these bodies are
 * replaced by theirs; they throw until then, so neither can pass for an answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantAdmission
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The tenant the principal is to act in for the selection (`null` for
     * none), once the tenant access contract admits it and it is active, or
     * `tenant_ineligible` or `tenant_inactive`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \LogicException
     */
    public static function select(Principal $principal, TenantSelection $selection): FailureReason|Tenant|null
    {
        throw new \LogicException(sprintf('TenantAdmission::select() for %s (%s) is not built yet.', $principal::class, $selection->tenantId() ?? 'no id'));
    }

    /**
     * The session's recorded active tenant (`null` for none), active, and with
     * `$checkAccess` admitted by the tenant access contract, or
     * `tenant_inactive` or `tenant_ineligible`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $tenantId
     * @param  bool  $checkAccess
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \LogicException
     */
    public static function recorded(Principal $principal, ?string $tenantId, bool $checkAccess): FailureReason|Tenant|null
    {
        $access = $checkAccess ? 'checked' : 'unchecked';

        throw new \LogicException(sprintf('TenantAdmission::recorded() for %s (%s, %s) is not built yet.', $principal::class, $tenantId ?? 'none', $access));
    }
}
