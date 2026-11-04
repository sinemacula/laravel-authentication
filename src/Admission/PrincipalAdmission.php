<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Whether a principal may hold a session of an application, or act for it with
 * a machine credential: the principal is active, the tenant it belongs to (its
 * own, not the one a session acts in) is active, and the application's
 * `ApplicationAccess` lets it use the application.
 *
 * The access question is asked inside `WriteConnection::during()` for the
 * principal, with the binding in effect when it is asked, so an application or
 * an adapter that rebinds it is heard at once, however long the caller lives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PrincipalAdmission
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the principal may not hold a session of the application, or `null`
     * when it may: `principal_inactive`, then `tenant_inactive` for its own
     * tenant (inactive, or opted into activation and not loadable), then
     * `principal_ineligible` when `ApplicationAccess` refuses it.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function refusal(string $guard, Principal $principal): ?FailureReason
    {
        return ActivationPolicy::isActive($principal) ? self::refusalOfActive($guard, $principal) : FailureReason::PRINCIPAL_INACTIVE;
    }

    /**
     * Why a principal whose own activity the caller has checked may not hold a
     * session of the application, or `null` when it may: `tenant_inactive` for
     * its own tenant, then `principal_ineligible` when `ApplicationAccess`
     * refuses it, as `refusal()` judges an active principal.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function refusalOfActive(string $guard, Principal $principal): ?FailureReason
    {
        return match (true) {
            !ActivationPolicy::isTenantActive($principal) => FailureReason::TENANT_INACTIVE,
            !self::mayUse($guard, $principal)             => FailureReason::PRINCIPAL_INELIGIBLE,
            default                                       => null,
        };
    }

    /**
     * Whether `ApplicationAccess` lets the principal use the application, asked
     * on the write connection for the principal. For a caller that has checked
     * the principal's activity itself.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function mayUse(string $guard, Principal $principal): bool
    {
        $access = Container::getInstance()->make(ApplicationAccess::class);

        return WriteConnection::during($principal, static fn (): bool => $access->mayUse($guard, $principal));
    }
}
