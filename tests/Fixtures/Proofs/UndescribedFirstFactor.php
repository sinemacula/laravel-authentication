<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Proofs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;

/**
 * Makes an identity's first factor with an unknown channel, no observed
 * properties and no `amr` values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UndescribedFirstFactor
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The undescribed first factor of the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Proofs\FirstFactor
     */
    public static function of(Identity $identity): FirstFactor
    {
        return new FirstFactor($identity, new Channel(ChannelKind::UNKNOWN));
    }
}
