<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Audience;

use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * Reads a principal's type: the categorical label (e.g. `staff`, `service`)
 * that access tokens carry in `pty`, `Auth::type()` returns, and a guard's
 * audience policy keys eligibility and lifetimes on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PrincipalType
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The principal's own type when it implements `HasType` and reports one,
     * otherwise the type of the tenant it acts within when that tenant does,
     * otherwise `null`. An empty type reads as none, so a principal whose type
     * column is empty falls back to its tenant's.
     *
     * The tenant is loaded only when the principal has no type of its own. Both
     * reads run inside `WriteConnection::during()` for the principal, so a type
     * that decides eligibility cannot come from a lagging replica, and the
     * tenant is read as `getTenant()` reads it, with its exceptions.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    public static function of(Principal $principal): ?string
    {
        return WriteConnection::during($principal, static function () use ($principal): ?string {

            $type = self::reported($principal);

            if ($type !== null) {
                return $type;
            }

            $tenant = $principal->getTenant();

            return $tenant === null ? null : self::reported($tenant);
        });
    }

    /**
     * The principal's type from what is already loaded, with no read: its own
     * when it reports one, otherwise the given tenant's, otherwise `null`. An
     * event's context records it this way, with the tenant its flow loaded. A
     * type that cannot be read without its column (`ProvidesType`) throws a
     * `LogicException`, as `of()` does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?string
     *
     * @throws \LogicException
     */
    public static function loaded(Principal $principal, ?Tenant $tenant): ?string
    {
        return self::reported($principal) ?? ($tenant === null ? null : self::reported($tenant));
    }

    /**
     * The type the subject reports, or `null` when it declares none or reports
     * an empty one.
     *
     * @param  object  $subject
     * @return ?string
     *
     * @throws \LogicException
     */
    private static function reported(object $subject): ?string
    {
        $type = $subject instanceof HasType ? $subject->getType() : '';

        return $type === '' ? null : $type;
    }
}
