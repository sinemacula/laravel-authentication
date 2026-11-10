<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Makes the sign-in proof of a first factor nothing described: an unknown
 * channel, no observed properties and no `amr` values, verified at the given
 * time. For tests that need some first factor and care about none of its
 * detail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UndescribedSignInProof
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The proof of an undescribed first factor under the named method.
     *
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Proofs\SignInProof
     */
    public static function of(string $method, CarbonImmutable $at): SignInProof
    {
        return SignInProof::verified($method, new FirstFactor(new PlainIdentityFixture(1), new Channel(ChannelKind::UNKNOWN)), $at);
    }
}
