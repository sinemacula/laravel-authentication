<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Fixtures\Proofs\UndescribedSignInProof;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Unit tests for a tenant authentication policy's answer, the default policy, a
 * verdict and a sign-in's evidence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantRequirement::class)]
#[CoversClass(RequireNothingOfTenants::class)]
#[CoversClass(TenantPolicyVerdict::class)]
#[CoversClass(SessionEvidence::class)]
#[CoversClass(TenantPolicyContext::class)]
#[CoversClass(TenantPolicyStanding::class)]
final class TenantRequirementTest extends TestCase
{
    /**
     * The default answer requires nothing and has no version; the default
     * policy gives it whatever it is asked about.
     *
     * @return void
     */
    public function testTheDefaultPolicyRequiresNothing(): void
    {
        $context = new TenantPolicyContext('api', new PlainIdentityFixture(7), new PlainPrincipalFixture(7), new PlainTenantFixture(1), null);
        $answer  = (new RequireNothingOfTenants)->requirementFor($context);

        self::assertNull($answer->version);
        self::assertTrue($answer->factor->isEmpty());
        self::assertNull($answer->connections);
        self::assertTrue($answer->admitsConnection(null));
        self::assertSame('api', $context->application);
    }

    /**
     * Named connections admit only a session established through one of them;
     * an empty list admits none, and no connection never meets a list.
     *
     * @return void
     */
    public function testConnectionsAdmitOnlyTheSessionsEstablishedThroughThem(): void
    {
        $named = new TenantRequirement('v1', new Requirement(new RequirementPart), ['conn-a', 'conn-b']);

        self::assertTrue($named->admitsConnection('conn-b'));
        self::assertFalse($named->admitsConnection('conn-c'));
        self::assertFalse($named->admitsConnection(null));
        self::assertSame(['conn-a', 'conn-b'], $named->connections);
        self::assertSame('v1', $named->version);

        $none = new TenantRequirement(connections: []);

        self::assertSame([], $none->connections);
        self::assertFalse($none->admitsConnection('conn-a'));
    }

    /**
     * Rows of `[version, connections, message]` an answer refuses.
     *
     * @return iterable<string, array{0: ?string, 1: ?array<array-key, mixed>, 2: string}>
     */
    public static function provideRefusedAnswers(): iterable
    {
        $version     = 'A tenant policy version must be between 1 and 64 characters.';
        $connections = 'A tenant policy\'s connections must be a list of non-empty connection ids.';

        yield 'an empty version' => ['', null, $version];
        yield 'a version over 64 characters' => [str_repeat('v', 65), null, $version];
        yield 'connections keyed by name' => [null, ['primary' => 'conn-a'], $connections];
        yield 'an empty connection id' => [null, ['conn-a', ''], $connections];
        yield 'a connection id that is not a string' => [null, [7], $connections];
    }

    /**
     * A version must be 1 to 64 characters, and the connections a list of
     * non-empty ids.
     *
     * @param  ?string  $version
     * @param  ?array<array-key, mixed>  $connections
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedAnswers')]
    public function testAMalformedAnswerIsRefused(?string $version, ?array $connections, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new TenantRequirement($version, connections: $connections);
    }

    /**
     * A version of exactly 64 characters is kept, however many bytes they take.
     *
     * @return void
     */
    public function testAVersionOfTheLongestLengthIsKept(): void
    {
        self::assertSame(str_repeat('v', 64), (new TenantRequirement(str_repeat('v', 64)))->version);
        self::assertSame(str_repeat('é', 64), (new TenantRequirement(str_repeat('é', 64)))->version);
    }

    /**
     * A verdict is met only when the session meets the policy.
     *
     * @return void
     */
    public function testAVerdictIsMetOnlyWhenTheSessionMeetsThePolicy(): void
    {
        self::assertTrue((new TenantPolicyVerdict(TenantPolicyStanding::MET, 'v1'))->isMet());
        self::assertFalse((new TenantPolicyVerdict(TenantPolicyStanding::FACTOR_REQUIRED, null))->isMet());
        self::assertFalse((new TenantPolicyVerdict(TenantPolicyStanding::SSO_REQUIRED, null))->isMet());
        self::assertSame(['met', 'factor_required', 'sso_required'], array_column(TenantPolicyStanding::cases(), 'value'));
    }

    /**
     * A sign-in's evidence is its first factor, under the id the session
     * records it with, and the connection an external provider established it
     * through, if one did.
     *
     * @return void
     */
    public function testASignInsEvidenceIsWhatItProved(): void
    {
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $password = UndescribedSignInProof::of('password', $now);
        $evidence = SessionEvidence::of($password);

        self::assertSame($password->id, $evidence->firstFactor->id);
        self::assertSame([$evidence->firstFactor], $evidence->proofs);
        self::assertNull($evidence->connectionId);

        self::assertSame('conn-a', SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a'), $now))->connectionId);
    }
}
