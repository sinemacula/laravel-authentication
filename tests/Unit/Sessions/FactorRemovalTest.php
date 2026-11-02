<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;

/**
 * Unit tests for what a factor's removal did to the identity's sessions: how
 * many it revoked, whether the current session was among them, and the pending
 * session and credential the current session returned to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRemoval::class)]
final class FactorRemovalTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A removal that kept the current session active, or had none, counts what
     * it revoked and returned nothing to pending.
     *
     * @return void
     */
    public function testARemovalThatKeptTheCurrentSessionReturnedNothingToPending(): void
    {
        $removal = new FactorRemoval(3);

        self::assertSame(3, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertNull($removal->pending);
        self::assertNull($removal->credential);
        self::assertFalse($removal->isPending());
    }

    /**
     * A removal that revoked the current session says so.
     *
     * @return void
     */
    public function testARemovalThatRevokedTheCurrentSessionSaysSo(): void
    {
        $removal = new FactorRemoval(2, true);

        self::assertSame(2, $removal->revoked);
        self::assertTrue($removal->currentRevoked);
        self::assertFalse($removal->isPending());
    }

    /**
     * A removal that returned the current session to pending carries the
     * pending session and its credential.
     *
     * @return void
     */
    public function testARemovalThatReturnedTheCurrentSessionToPendingCarriesIt(): void
    {
        $pending = new PendingSession(
            'session-1',
            'api',
            \Mockery::mock(Identity::class),
            null,
            null,
            [PendingRequirement::MFA],
            'password',
            CarbonImmutable::parse('2026-04-06 12:05:00'),
            \Mockery::mock(Session::class),
            new Requirement(new RequirementPart),
            SignInProof::unattested('password', CarbonImmutable::parse('2026-04-06 12:00:00'))->recorded(),
        );

        $credential = new Secret('session-1.secret');
        $removal    = new FactorRemoval(1, false, $pending, $credential);

        self::assertSame(1, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertSame($pending, $removal->pending);
        self::assertSame($credential, $removal->credential);
        self::assertTrue($removal->isPending());
    }
}
