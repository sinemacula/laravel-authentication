<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

/**
 * Unit tests for what judging the current session again after a factor change
 * did to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeResult::class)]
final class FactorChangeResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of `[the result, its status]`: every outcome that carries nothing.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult, 1: \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideOutcomesWithoutAPayload(): iterable
    {
        yield 'kept active' => [static fn (): FactorChangeResult => FactorChangeResult::active(), FactorChangeStatus::ACTIVE];
        yield 'revoked' => [static fn (): FactorChangeResult => FactorChangeResult::revoked(), FactorChangeStatus::REVOKED];
        yield 'skipped' => [static fn (): FactorChangeResult => FactorChangeResult::skipped(), FactorChangeStatus::SKIPPED];
    }

    /**
     * A session kept active, revoked or skipped is named by its status and its
     * own predicate alone, and carries no pending session or credential.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult  $result
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus  $status
     * @return void
     */
    #[DataProvider('provideOutcomesWithoutAPayload')]
    public function testAnOutcomeWithoutAPayloadCarriesNothing(\Closure $result, FactorChangeStatus $status): void
    {
        $answer = $result();

        self::assertSame($status, $answer->status);
        self::assertSame(self::predicates($status), self::answered($answer));
        self::assertNull($answer->pending);
        self::assertNull($answer->credential);
    }

    /**
     * A session returned to pending is named by its status and `isPending()`
     * alone, and carries the pending session and the pending credential.
     *
     * @return void
     */
    public function testAReturnToPendingCarriesThePendingSessionAndItsCredential(): void
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
            UndescribedSignInProof::of('password', CarbonImmutable::parse('2026-04-06 12:00:00'))->recorded(),
        );

        $credential = new Secret('session-1.secret');
        $answer     = FactorChangeResult::pending($pending, $credential);

        self::assertSame(FactorChangeStatus::PENDING, $answer->status);
        self::assertSame(self::predicates(FactorChangeStatus::PENDING), self::answered($answer));
        self::assertSame($pending, $answer->pending);
        self::assertSame($credential, $answer->credential);
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(FactorChangeResult::class, '__construct'))->isPrivate());
    }

    /**
     * What each predicate answers for the result, by its status.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult  $result
     * @return array<string, bool>
     */
    private static function answered(FactorChangeResult $result): array
    {
        return [
            'active'  => $result->isActive(),
            'pending' => $result->isPending(),
            'revoked' => $result->isRevoked(),
            'skipped' => $result->isSkipped(),
        ];
    }

    /**
     * What each predicate should answer for the status: `true` for its own
     * alone.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus  $status
     * @return array<string, bool>
     */
    private static function predicates(FactorChangeStatus $status): array
    {
        $answers = [];

        foreach (FactorChangeStatus::cases() as $case) {
            $answers[$case->value] = $case === $status;
        }

        return $answers;
    }
}
