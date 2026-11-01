<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Application access contract: may this principal use this application?
 *
 * Answered from the application's own data (its tenant tree, its roles, a grant
 * table), never interpreted by the package beyond yes or no. The package asks
 * it wherever a principal is to hold or keep a session of an application, or a
 * machine credential is to act for one: at sign-in, at the choice of principal,
 * when listing the principals an identity may use, on every switch, on refresh,
 * and for API keys and client credentials. A principal it refuses fails as
 * `principal_ineligible` (a client credentials exchange answers
 * `unauthorized_client`).
 *
 * The package asks it inside `WriteConnection::during()` for the principal, so
 * a model read it makes, and a query-builder read on the principal's own
 * connection, sees the primary rather than a replica that may lag behind a
 * withdrawn grant; any other query-builder read pins itself with
 * `WriteConnection::query()`. The default (`AdmitAnyPrincipal`) lets any
 * principal use any application. A rebound implementation that holds request
 * state is bound `scoped`, not `singleton`, so a long-running worker does not
 * carry it from one request to the next.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationAccess
{
    /**
     * Whether the principal may use the application (its guard's name).
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public function mayUse(string $application, Principal $principal): bool;
}
