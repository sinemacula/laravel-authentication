<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Makes a change of identifier whose proof was accepted, inside the
 * confirmation's transaction on the identity's connection, which is also the
 * pending changes' and the codes' (the service refuses one that is not).
 *
 * In order: the pending change is deleted while it still names its request (a
 * concurrent confirmation or a newer request wins otherwise); the guard's
 * identity provider must find no other identity holding the new identifier
 * (best effort: the application's unique index on the column is what decides a
 * race); every proof the change outdates is invalidated in one statement; and
 * the identity's identifier is replaced while it is still the one the change
 * was requested against, which records the new one as verified. A refusal at
 * any step throws `ChangeRefused`, so the transaction rolls back and the proof,
 * the pending change and the identifier stay as they were. Once the transaction
 * commits, and never if it rolls back, `IdentifierChanged` is dispatched and,
 * when the identity had an identifier of the type before, the notice to it is
 * queued.
 *
 * Invalidated, for every `jwt` guard whose provider can return the identity
 * (see `JwtGuards::namesFor()`: a guard over another table binds its proofs to
 * other identities) and for both the replaced identifier (in its canonical
 * form) and the new one: the sign-in, password reset and password reset link
 * codes of the identifier, and the identity's verification code for it. A
 * verification link needs nothing: it carries the digest of the identifier it
 * verifies, so it stops working once that is not the identity's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChangeConfirmation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the change is confirmed through. */
        private GuardContext $context,

        /** Container the configuration, engine, verifier and delivery are resolved from. */
        private Container $container,
    ) {}

    /**
     * Make the change, or throw why it cannot be made.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused
     *
     * @imperative
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function complete(HasChangeableIdentifiers&Identity&Model $identity, IdentifierChange $change, EventContext $context, CarbonImmutable $now): void
    {
        if (!PendingChanges::delete($change)) {
            throw new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS);
        }

        if ($this->isHeldByAnother($identity, $change)) {
            throw new ChangeRefused(IdentifierChangeOutcome::TAKEN, FailureReason::IDENTIFIER_TAKEN);
        }

        $this->container->make(OneTimeCodes::class)->invalidate($this->outdatedProofs($identity, $change));

        try {
            $replaced = $identity->replaceIdentifier($change->type, $change->previous, $change->identifier);
        } catch (UniqueConstraintViolationException) {
            throw new ChangeRefused(IdentifierChangeOutcome::TAKEN, FailureReason::IDENTIFIER_TAKEN);
        }

        if (!$replaced) {
            throw new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS);
        }

        $this->report($identity, $change, $context, $now);
    }

    /**
     * Whether the guard's identity provider, reading the write connection,
     * finds an identity other than this one (another row) holding the new
     * identifier.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @return bool
     */
    private function isHeldByAnother(Identity&Model $identity, IdentifierChange $change): bool
    {
        $provider = $this->context->provider();
        $holder   = WriteConnection::during($identity, static fn (): mixed => $provider->retrieveByCredentials([$change->type => $change->identifier]));

        return $holder !== null && !($holder instanceof Identity && AccountAttempts::account($holder) === AccountAttempts::account($identity));
    }

    /**
     * The bindings of every code the change outdates.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @return list<\SineMacula\Laravel\Authentication\Codes\CodeBinding>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function outdatedProofs(Identity&Model $identity, IdentifierChange $change): array
    {
        $type        = $change->type;
        $previous    = $change->previous === null ? null : $this->container->make(IdentifierVerifier::class)->canonical($type, $change->previous);
        $identifiers = array_filter([$previous, $change->identifier], is_string(...));
        $bindings    = [];

        foreach (JwtGuards::namesFor($identity, $this->container->make(Repository::class)) as $guard) {
            foreach ($identifiers as $identifier) {
                $bindings[] = CodeBinding::signIn($guard, $type, $identifier);
                $bindings[] = CodeBinding::passwordReset($guard, $type, $identifier);
                $bindings[] = CodeBinding::passwordResetLink($guard, $type, $identifier);
                $bindings[] = CodeBinding::verification($guard, $type, $identifier, $identity);
            }
        }

        return $bindings;
    }

    /**
     * Once the change commits, dispatch `IdentifierChanged` and queue the
     * notice to the identifier it replaced, when there was one.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function report(Identity&Model $identity, IdentifierChange $change, EventContext $context, CarbonImmutable $now): void
    {
        $container = $this->container;
        $event     = new IdentifierChanged($context, $change->type, $change->previous, $change->identifier, $now);

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($identity, fn () => $this->context->dispatch($event));

        if ($change->previous === null) {
            return;
        }

        $notice = new IdentifierChangeNotice($change->guard, $change->type, $change->previous, $change->previous_verified, $change->identifier, $identity, $now);

        $container->make(QueuedDelivery::class)->dispatch(new SendIdentifierChangeNotice($notice), $identity);
    }
}
