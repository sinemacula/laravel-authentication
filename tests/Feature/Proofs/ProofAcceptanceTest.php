<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use Tests\Concerns\InteractsWithProofs;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Tests of which proofs a pending session takes as the further factor it waits
 * for, decided on the session as it is held, with no query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofAcceptance::class)]
final class ProofAcceptanceTest extends TestCase
{
    use InteractsWithProofs;

    /** @var string The pending session's key. */
    private const string SESSION = '0190e1a4-0000-7000-8000-0000000000aa';

    /**
     * Rows of `[kind, purpose]` a pending session takes.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, 1: \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose}>
     */
    public static function provideTakenProofs(): iterable
    {
        yield 'a further factor for the sign-in' => [ProofKind::ADDITIONAL_FACTOR, Purpose::SIGN_IN];
        yield 'a recovery code for the sign-in' => [ProofKind::RECOVERY_CODE, Purpose::SIGN_IN];
        yield 'the factor confirming a bootstrap enrolment' => [ProofKind::ADDITIONAL_FACTOR, Purpose::ENROLLMENT];
    }

    /**
     * A further factor or a recovery code made for the sign-in, or a further
     * factor confirming an enrolment, accepted, made by the session's owner on
     * the guard for the session, between when the session began waiting and
     * now, both seconds included, is taken.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('provideTakenProofs')]
    public function testTakesAProofMadeForThePendingSession(ProofKind $kind, Purpose $purpose): void
    {
        $identity = self::identity();
        $since    = CarbonImmutable::parse('2026-04-06 12:00:00');
        $now      = $since->addMinute();

        foreach ([$since, $now] as $at) {
            self::assertNull(ProofAcceptance::forPendingSession(
                self::adapterProof($identity, 'api', self::SESSION, $purpose, $kind, $at),
                self::pendingSession($identity),
                'api',
                $since,
                $now,
            ));
        }
    }

    /**
     * Rows of `[changes, reason]`: what makes a proof one the pending session
     * refuses, alone or together.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedProofs(): iterable
    {
        $invalid = FailureReason::PROOF_INVALID;
        $binding = FailureReason::PROOF_BINDING_MISMATCH;

        yield 'a first factor' => [['kind' => ProofKind::FIRST_FACTOR], $invalid];
        yield 'an external reauthentication' => [['kind' => ProofKind::EXTERNAL_REAUTHENTICATION], $invalid];
        yield 'a step-up' => [['purpose' => Purpose::STEP_UP], $invalid];
        yield 'a reauthentication' => [['purpose' => Purpose::REAUTHENTICATE], $invalid];
        yield 'a recovery code for an enrolment' => [['kind' => ProofKind::RECOVERY_CODE, 'purpose' => Purpose::ENROLLMENT], $invalid];
        yield 'not accepted' => [['evaluation' => new Evaluation(false, true)], $invalid];
        yield 'made before the session waited' => [['at' => '2026-04-06 11:59:59'], $invalid];
        yield 'made after now' => [['at' => '2026-04-06 12:01:01'], $invalid];
        yield 'another identity' => [['identity' => 'other'], $binding];
        yield 'another model with the same key' => [['identity' => 'same key'], $binding];
        yield 'another application' => [['application' => 'admin'], $binding];
        yield 'another session' => [['session' => '0190e1a4-0000-7000-8000-0000000000bb'], $binding];
        yield 'not accepted, for another session' => [['evaluation' => new Evaluation(false, true), 'session' => '0190e1a4-0000-7000-8000-0000000000bb'], $invalid];
    }

    /**
     * A proof of another kind or purpose, not accepted, or made outside the
     * window is invalid; one made by another identity, on another application,
     * or for another session does not bind; and one that is both is invalid,
     * judged before its binding.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusedProofs')]
    public function testRefusesAProofNotMadeForThePendingSession(array $changes, FailureReason $reason): void
    {
        $identity    = self::identity();
        $made        = self::madeBy($changes['identity'] ?? null, $identity);
        $kind        = $changes['kind']        ?? ProofKind::ADDITIONAL_FACTOR;
        $purpose     = $changes['purpose']     ?? Purpose::SIGN_IN;
        $evaluation  = $changes['evaluation']  ?? new Evaluation(true, true);
        $application = $changes['application'] ?? 'api';
        $session     = $changes['session']     ?? self::SESSION;
        $at          = $changes['at']          ?? '2026-04-06 12:00:30';

        self::assertInstanceOf(ProofKind::class, $kind);
        self::assertInstanceOf(Purpose::class, $purpose);
        self::assertInstanceOf(Evaluation::class, $evaluation);
        self::assertIsString($application);
        self::assertIsString($at);

        $proof = self::adapterProof($made, $application, $session, $purpose, $kind, CarbonImmutable::parse($at), $evaluation);

        self::assertSame($reason, ProofAcceptance::forPendingSession(
            $proof,
            self::pendingSession($identity),
            'api',
            CarbonImmutable::parse('2026-04-06 12:00:00'),
            CarbonImmutable::parse('2026-04-06 12:01:00'),
        ));
    }

    /**
     * The identity a refused proof was made by: another identity, one of
     * another model with the same key, or the session's own.
     *
     * @param  mixed  $who
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function madeBy(mixed $who, Identity $identity): Identity
    {
        $made = match ($who) {
            'other'    => (new IntegrationIdentity)->forceFill(['id' => 8]),
            'same key' => (new ActivatableTenantMember)->forceFill(['id' => 7]),
            default    => $identity,
        };

        self::assertInstanceOf(Identity::class, $made);

        return $made;
    }

    /**
     * An identity of the `api` guard, held in memory.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private static function identity(): IntegrationIdentity
    {
        return (new IntegrationIdentity)->forceFill(['id' => 7]);
    }

    /**
     * A pending session of the identity, held in memory under its key.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private static function pendingSession(IntegrationIdentity $identity): Session
    {
        return (new Session)->forceFill([
            'id'                   => self::SESSION,
            'status'               => 'pending',
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => '7',
        ]);
    }
}
