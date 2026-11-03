<?php

declare(strict_types = 1);

namespace Tests\Feature\External;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceAcceptance;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests for deciding whether an external provider's evidence is
 * accepted at all, through the evidence policy bound in the container: only
 * when it meets multifactor authentication or an additional verification, and
 * then with what it met; never by default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvidenceAcceptance::class)]
final class EvidenceAcceptanceTest extends TestCase
{
    /**
     * By default no evidence is accepted, however strong.
     *
     * @return void
     */
    public function testNoEvidenceIsAcceptedByDefault(): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00');

        self::assertNull(EvidenceAcceptance::evaluate(new ExternalEvidence(['hwk', 'pin'], 'phrh', $now), self::subject($now)));
    }

    /**
     * Evidence the policy says meets multifactor authentication is accepted as
     * multifactor, after one question; evidence it says meets only an
     * additional verification is accepted, not as multifactor, after it was
     * asked for multifactor first; evidence that meets neither is not accepted.
     * Each question asks for the one part, of any age, about the subject, with
     * reads pinned to the write connection.
     *
     * @return void
     */
    public function testEvidenceIsAcceptedOnlyForWhatItMeets(): void
    {
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $evidence = new ExternalEvidence(['hwk'], null, $now->subMinute());
        $subject  = self::subject($now);

        $multifactor = $this->bind([RequirementKind::MULTIFACTOR]);

        self::assertEquals(new Evaluation(true, true), EvidenceAcceptance::evaluate($evidence, $subject));
        self::assertCount(1, $multifactor->asked);
        self::assertSame([RequirementKind::MULTIFACTOR], $multifactor->asked[0]['requirement']->kinds());
        self::assertNull($multifactor->asked[0]['requirement']->multifactor?->maxAgeSeconds);
        self::assertSame([$evidence, $subject, true], [$multifactor->asked[0]['evidence'], $multifactor->asked[0]['subject'], $multifactor->asked[0]['pinned']]);

        $additional = $this->bind([RequirementKind::ADDITIONAL_VERIFICATION]);

        self::assertEquals(new Evaluation(true, false), EvidenceAcceptance::evaluate($evidence, $subject));
        $kinds = array_map(static fn (array $asked): array => $asked['requirement']->kinds(), $additional->asked);

        self::assertSame([[RequirementKind::MULTIFACTOR], [RequirementKind::ADDITIONAL_VERIFICATION]], $kinds);
        self::assertNull($additional->asked[1]['requirement']->additionalVerification?->maxAgeSeconds);
        self::assertTrue($additional->asked[1]['pinned']);

        $neither = $this->bind([RequirementKind::PHISHING_RESISTANCE]);

        self::assertNull(EvidenceAcceptance::evaluate($evidence, $subject));
        self::assertCount(2, $neither->asked);
    }

    /**
     * Evidence dated after the time it is judged at is judged as of that time,
     * keeping its methods and context; evidence dated then or before is judged
     * as it is.
     *
     * @return void
     */
    public function testEvidenceFromTheFutureIsJudgedAsOfNow(): void
    {
        $now     = CarbonImmutable::parse('2026-04-06 12:00:00');
        $subject = self::subject($now);
        $policy  = $this->bind([RequirementKind::MULTIFACTOR]);
        $ahead   = new ExternalEvidence(['hwk'], 'phrh', $now->addMinutes(3));

        EvidenceAcceptance::evaluate($ahead, $subject);

        $judged = $policy->asked[0]['evidence'];

        self::assertSame([['hwk'], 'phrh', $now->getTimestamp()], [$judged->methods, $judged->context, $judged->authenticatedAt->getTimestamp()]);

        $atNow = new ExternalEvidence(['hwk'], null, $now);

        self::assertSame($atNow, EvidenceAcceptance::asOf($atNow, $subject));
    }

    /**
     * What the policy throws reaches the caller, so the transaction it was
     * asked in rolls back.
     *
     * @return void
     */
    public function testWhatThePolicyThrowsPropagates(): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00');

        app()->instance(ExternalEvidencePolicy::class, new class implements ExternalEvidencePolicy {
            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
             * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
             * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
             * @return bool
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
            {
                throw new \RuntimeException('The trust store is unavailable.');
            }
        });

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The trust store is unavailable.');

        EvidenceAcceptance::evaluate(new ExternalEvidence([], null, $now), self::subject($now));
    }

    /**
     * The acceptance is a static utility that cannot be instantiated from
     * outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(EvidenceAcceptance::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(EvidenceAcceptance::class, $instance);
    }

    /**
     * Bind a policy that trusts evidence for the kinds given.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>  $trusted
     * @return \Tests\Fixtures\External\ScriptedEvidencePolicy
     */
    private function bind(array $trusted): ScriptedEvidencePolicy
    {
        $policy = new ScriptedEvidencePolicy($trusted);

        app()->instance(ExternalEvidencePolicy::class, $policy);

        return $policy;
    }

    /**
     * The subject the evidence is judged for, at the time given.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\External\EvidenceSubject
     */
    private static function subject(CarbonImmutable $now): EvidenceSubject
    {
        return new EvidenceSubject(new PlainIdentityFixture(7), 'api', 'conn-a', $now);
    }
}
