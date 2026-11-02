<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;

/**
 * Unit tests for a session's standing against its tenant's authentication
 * policy: met only when it meets the policy, with the version it was judged by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyVerdict::class)]
final class TenantPolicyVerdictTest extends TestCase
{
    /**
     * Rows of `[standing, met]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding, 1: bool}>
     */
    public static function provideStandings(): iterable
    {
        yield 'met' => [TenantPolicyStanding::MET, true];
        yield 'a factor required' => [TenantPolicyStanding::FACTOR_REQUIRED, false];
        yield 'a connection required' => [TenantPolicyStanding::SSO_REQUIRED, false];
    }

    /**
     * A verdict is met only when the session meets the policy, and keeps the
     * version of the answer, none included.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding  $standing
     * @param  bool  $met
     * @return void
     */
    #[DataProvider('provideStandings')]
    public function testAVerdictIsMetOnlyWhenTheSessionMeetsThePolicy(TenantPolicyStanding $standing, bool $met): void
    {
        $verdict = new TenantPolicyVerdict($standing, 'v1');

        self::assertSame($met, $verdict->isMet());
        self::assertSame($standing, $verdict->standing);
        self::assertSame('v1', $verdict->version);
        self::assertNull((new TenantPolicyVerdict($standing, null))->version);
    }

    /**
     * A verdict names the further factor the session falls short of, and none
     * unless it was given one.
     *
     * @return void
     */
    public function testAVerdictNamesTheFactorItFallsShortOf(): void
    {
        $factor = new Requirement(multifactor: new RequirementPart(600));

        self::assertSame($factor, (new TenantPolicyVerdict(TenantPolicyStanding::FACTOR_REQUIRED, 'v1', $factor))->factor);
        self::assertTrue((new TenantPolicyVerdict(TenantPolicyStanding::MET, 'v1'))->factor->isEmpty());
        self::assertNull((new TenantPolicyVerdict(TenantPolicyStanding::MET, 'v1'))->firstFactor);
    }

    /**
     * The standings carry their stable values.
     *
     * @return void
     */
    public function testTheStandingsCarryTheirValues(): void
    {
        $values = array_map(static fn (TenantPolicyStanding $standing): string => $standing->value, TenantPolicyStanding::cases());

        self::assertSame(['met', 'factor_required', 'sso_required'], $values);
    }
}
