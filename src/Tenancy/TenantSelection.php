<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Which tenant a session is to act in: the principal's own (or none, for a
 * platform principal), none, or a tenant named by its opaque id, which the
 * application's tenant resolver loads and its tenant access contract admits.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantSelection
{
    /** @var int Longest tenant id, in characters: the session column's length. */
    public const int ID_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  bool  $principalDefault
     * @param  ?string  $tenantId
     */
    private function __construct(

        /** Whether the selection is the principal's own tenant. */
        private bool $principalDefault,

        /** The tenant named, for a selection of one. */
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
     * The tenant with the opaque id, stringified as the session records it.
     *
     * @param  int|string  $tenantId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(int|string $tenantId): self
    {
        $id = (string) IdentifierCoercion::stringify($tenantId);

        if ($id === '' || mb_strlen($id) > self::ID_MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant id must be from 1 to %d characters.', self::ID_MAX_LENGTH));
        }

        return new self(false, $id);
    }

    /**
     * Whether the selection is the principal's own tenant.
     *
     * @return bool
     */
    public function isPrincipalDefault(): bool
    {
        return $this->principalDefault;
    }

    /**
     * The tenant id named, or `null` for none and for the principal's own.
     *
     * @return ?string
     */
    public function tenantId(): ?string
    {
        return $this->tenantId;
    }
}
