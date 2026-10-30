<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

/**
 * 3D principal variant whose attribute and relation names build on the trait's
 * defaults: `member_id`, `memberIdentity` and `memberTenant`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Stub3dPrincipalWithMemberNames extends Stub3dPrincipal
{
    /**
     * Prefix the default identifier attribute.
     *
     * @return string
     */
    #[\Override]
    protected function getPrincipalIdentifierName(): string
    {
        return 'member_' . parent::getPrincipalIdentifierName();
    }

    /**
     * Prefix the default identity relation.
     *
     * @return string
     */
    #[\Override]
    protected function getIdentityRelationName(): string
    {
        return 'member' . ucfirst(parent::getIdentityRelationName());
    }

    /**
     * Prefix the default tenant relation.
     *
     * @return string
     */
    #[\Override]
    protected function getTenantRelationName(): string
    {
        return 'member' . ucfirst(parent::getTenantRelationName());
    }
}
