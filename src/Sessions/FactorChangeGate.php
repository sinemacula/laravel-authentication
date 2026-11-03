<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Factors\FactorReference;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;

/**
 * The gate the factor package asks before it changes one of an identity's
 * further factors (adding, replacing or removing one) or generates its recovery
 * codes, from the active session the change is made on.
 *
 * In one transaction on the session model's connection (a savepoint in the
 * caller's), the session's row is locked until that transaction ends, so a
 * revocation either commits first and the change is refused, or waits for the
 * change. The locked row must still be the session given (its generation and
 * owner), this guard's, not revoked, not pending (a pending session enrols its
 * bootstrap factor through the pending credential's actions instead) and not
 * ended, and a person's. Then the freshness policy judges it for the change's
 * operation: `first_additional_factor` for an identity's first additional
 * factor, which has no factor to step up with and so takes a reauthentication
 * with the first factor (`reauthentication_required`), and `factor_change` for
 * every other change, which takes a step-up (`step_up_required`). A replacement
 * or removal names the factor it acts on, whose own proofs never count. The
 * stricter of the caller's requirement and the configured one applies.
 *
 * It decides; it writes nothing and reports nothing. Whether the identity
 * already has a further factor, and what an added factor's destination is, are
 * the factor package's to know.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorChangeGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are gated. */
        private GuardContext $context,

        /** Container the freshness policy is resolved from. */
        private Container $container,
    ) {}

    /**
     * Whether the change may be made from the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $factor
     * @return \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function verdict(Session $session, FactorChange $change, ?FreshnessRequirement $requirement, ?string $factor): FactorChangeVerdict
    {
        self::assertFactor($change, $factor);

        return SessionLookup::model()->getConnection()->transaction(fn (): FactorChangeVerdict => $this->judge($session, $change, $requirement, $factor));
    }

    /**
     * Lock the session and judge it for the change, in the transaction.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $factor
     * @return \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function judge(Session $session, FactorChange $change, ?FreshnessRequirement $requirement, ?string $factor): FactorChangeVerdict
    {
        $locked = $this->locked($session, CarbonImmutable::now()->startOfSecond());

        if ($locked instanceof FailureReason) {
            return FactorChangeVerdict::refused($locked);
        }

        $policy    = $this->container->make(FreshnessPolicy::class);
        $operation = $change->operation();
        $effective = $policy->requirement($this->context->name(), $operation, $requirement);
        $proof     = $effective === null ? null : $policy->freshProof($locked, $operation, $requirement, $factor);

        if ($effective === null || $proof === null) {
            return FactorChangeVerdict::refused($change === FactorChange::ADD_FIRST ? FailureReason::REAUTHENTICATION_REQUIRED : FailureReason::STEP_UP_REQUIRED);
        }

        return FactorChangeVerdict::allowed($proof, $proof->authenticatedAt->addSeconds($effective->maxAgeSeconds));
    }

    /**
     * The session's row, locked, when a change may be made from it; else why
     * not: none stored under the key, or another session put there
     * (`session_unknown`); another guard's, revoked, pending or ended
     * (`OwnedSession::refusal()`); a machine identity's (`machine_identity`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function locked(Session $session, CarbonImmutable $now): (EloquentSession&Model)|FailureReason
    {
        $locked = SessionLookup::lock($session->getSessionIdentifier());

        if (!SessionOwnership::isSameSession($session, $locked)) {
            return FailureReason::SESSION_UNKNOWN;
        }

        return OwnedSession::refusal($locked, $this->context->name(), $now) ?? (SessionOwnership::isMachineOwned($locked) ? FailureReason::MACHINE_IDENTITY : $locked);
    }

    /**
     * Refuse a factor named for a change that names none, or none named (or one
     * empty or longer than 255 characters) for a replacement or removal, before
     * anything is read.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  ?string  $factor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertFactor(FactorChange $change, ?string $factor): void
    {
        if (!$change->namesFactor() && $factor !== null) {
            throw new \InvalidArgumentException(sprintf('A factor change of [%s] names no factor.', $change->value));
        }

        if ($change->namesFactor() && !FactorReference::isValid($factor)) {
            $message = sprintf('A factor change of [%s] names the factor it acts on, of 1 to %d characters.', $change->value, FactorReference::MAX_LENGTH);

            throw new \InvalidArgumentException($message);
        }
    }
}
