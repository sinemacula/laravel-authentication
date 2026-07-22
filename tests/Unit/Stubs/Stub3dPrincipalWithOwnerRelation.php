<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

/**
 * 3D principal variant that overrides the identity relation name to `owner`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Stub3dPrincipalWithOwnerRelation extends Stub3dPrincipal
{
    /**
     * Override the identity relation name.
     *
     * @return string
     */
    #[\Override]
    protected function getIdentityRelationName(): string
    {
        return 'owner';
    }
}
