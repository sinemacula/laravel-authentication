<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\HasOne;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Session model whose revocation comes from a `SessionRevocation` relation it
 * always eager-loads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EagerRevocationLogSession extends Session
{
    /** @var list<string> The relations to eager load on every query. */
    protected $with = ['revocation'];

    /**
     * Return when the eager-loaded revocation revoked the session, falling back
     * to the session's own column.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        $revocation = $this->getRelationValue('revocation');

        return $revocation instanceof SessionRevocation ? $revocation->revoked_at : parent::getRevokedAt();
    }

    /**
     * The recorded revocation of the session, if any.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasOne<\Tests\Integration\Fixtures\SessionRevocation, $this>
     */
    public function revocation(): HasOne
    {
        return $this->hasOne(SessionRevocation::class, 'session_id');
    }
}
