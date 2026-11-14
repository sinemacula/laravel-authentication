<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\RefuseFactorCodes;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the default factor code counters, which refuse every code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefuseFactorCodes::class)]
final class RefuseFactorCodesTest extends TestCase
{
    /**
     * Every admission and every report is refused as `type_not_enabled`,
     * whether the attempt matched or not.
     *
     * @return void
     */
    public function testRefusesEveryCode(): void
    {
        $counters = new RefuseFactorCodes;
        $proof    = new ProofBinding(new PlainIdentityFixture(7), 'mobile', 'session-1', Purpose::SIGN_IN);
        $binding  = new FactorCodeBinding($proof, 'factor-1', new Channel(ChannelKind::SMS, '+447700900123'));
        $client   = new ClientContext('203.0.113.7', 'Phone/1.0');

        $answers = [$counters->admit($binding, $client), $counters->report($binding, 'challenge-1', true, $client), $counters->report($binding, 'challenge-1', false, $client)];

        foreach ($answers as $answer) {
            self::assertSame([FactorCodeStanding::REFUSED, FactorCodeRefusal::TYPE_NOT_ENABLED, null], [$answer->standing, $answer->refusal, $answer->lockedUntil]);
        }
    }
}
