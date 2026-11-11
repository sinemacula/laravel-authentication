<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Application access that lets a principal use the application only with a
 * grant row on the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantedApplicationAccess implements ApplicationAccess
{
    /** @var string Table of the principals the application admits. */
    public const string GRANTS = 'application_grants';

    /**
     * Let a principal with a grant row use the application.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    #[\Override]
    public function mayUse(string $application, Principal $principal): bool
    {
        return DB::table(self::GRANTS)
            ->where('principal_type', $principal::class)
            ->where('principal_id', IdentifierCoercion::stringify($principal->getPrincipalIdentifier()))
            ->exists();
    }
}
