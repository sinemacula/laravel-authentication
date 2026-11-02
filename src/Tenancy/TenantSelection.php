<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

/**
 * The tenant a sign-in, a choice of principal or a switch asks a session to act
 * in: the principal's default (its own tenant, or none for a platform
 * principal), none, or a tenant named by its opaque identifier.
 *
 * A selection is a request, not an admission: the package resolves a named
 * tenant (the principal's own without asking the `TenantResolver`, any other
 * through it), asks `TenantAccess` whether the principal may act in it, and
 * checks it is active, before a session records it as its active tenant.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantSelection
{
    /** @var int Longest tenant identifier a session records, in characters. */
    public const int ID_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  bool  $principalDefault
     * @param  ?string  $tenantId
     */
    private function __construct(

        /** Whether the selection is the principal's default. */
        private bool $principalDefault,

        /** The tenant named, when one is. */
        private ?string $tenantId,
    ) {}

    /**
     * The principal's own tenant, or none for a platform principal.
     *
     * @return self
     */
    public static function principalDefault(): self
    {
        return new self(true, null);
    }

    /**
     * No tenant.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self(false, null);
    }

    /**
     * The tenant the identifier names, stringified as a session records it.
     *
     * @param  int|string  $tenantId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(int|string $tenantId): self
    {
        $id = (string) $tenantId;

        if ($id === '' || mb_strlen($id) > self::ID_MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant identifier must be between 1 and %d characters.', self::ID_MAX_LENGTH));
        }

        return new self(false, $id);
    }

    /**
     * Whether the selection is the principal's default.
     *
     * @return bool
     */
    public function isPrincipalDefault(): bool
    {
        return $this->principalDefault;
    }

    /**
     * The identifier of the tenant named, or `null` for none and for the
     * principal's default.
     *
     * @return ?string
     */
    public function tenantId(): ?string
    {
        return $this->tenantId;
    }
}
