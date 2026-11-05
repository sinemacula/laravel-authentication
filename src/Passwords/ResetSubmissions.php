<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Resets passwords for a guard with a link's token or a code: the proof is
 * spent in the same transaction as the new password, the identity's cutoff and
 * the revocation of every one of its sessions, or not at all.
 *
 * In order: the settings fail closed, and the provider's configured model must
 * live on the storage connection (see `SharedConnection`; a provider that names
 * no model has the identity it finds checked once the proof is accepted); the
 * identifier as given and the IP address must have submissions left
 * (`password_reset`, taken before any other work, so a flood of guesses never
 * reaches the hasher or the breached check, and given back only by a reset that
 * succeeds). Then, inside the guard's credential timebox: a malformed
 * identifier, token, code, challenge id (a code names the challenge it was sent
 * for) or password is `invalid`; a password the policy rejects is
 * `password_rejected`, with nothing spent; the identity is looked up (see
 * `ResetRecipient`); and, in one transaction on the codes' connection, the row
 * of an eligible one is locked and judged again as stored, then the proof is
 * checked whatever the identity, a code counting its attempt as a sign-in's
 * does. A refused proof commits (the attempt stays counted) and is `invalid`;
 * an accepted proof for no identity, or one that may not reset, rolls back, so
 * the proof stays unspent, and is `invalid`; an accepted proof for an eligible
 * identity sets the password (see `PasswordWriter`, flow `reset`) and commits.
 * Any exception rolls everything back together, at once outside a caller's
 * transaction and inside one once the caller rolls back. Inside a caller's
 * transaction the reset is a nested transaction of it: after a concurrency
 * error the caller rolls back, never commits, and retries whole (see
 * `spend()`).
 *
 * Every refusal but a rejected password is reported by `AuthenticationFailed`
 * (`password_reset`) with its reason; the result says only `invalid`. A reset
 * signs no one in and verifies no identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResetSubmissions
{
    /** @var string What the flow is called in a connection refusal. */
    public const string FLOW = 'A password reset';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose identities reset their passwords. */
        private GuardContext $context,

        /** Ends every session of an identity whose password is reset. */
        private SessionRevocations $revocations,

        /** Container the settings, policies, limiter, engine and hasher are resolved from. */
        private Container $container,
    ) {}

    /**
     * Reset with a link's token, the input naming the identifier under the
     * guard's password identifier, the `token` and the new `password`.
     *
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     *
     * @throws \Throwable
     */
    public function link(#[\SensitiveParameter] array $input, ?ClientContext $client): ResetResult
    {
        $type = $this->container->make(PasswordSignIn::class)->identifierType($this->context->name());

        return $this->reset(CodePurpose::PASSWORD_RESET_LINK, $type, ResetInput::TOKEN_KEY, $input, $client);
    }

    /**
     * Reset with a code, the input naming the identifier under the type (which
     * must have a registered normaliser), the `code`, the `challenge` it was
     * sent for and the new `password`.
     *
     * @param  string  $type
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     *
     * @throws \Throwable
     */
    public function code(string $type, #[\SensitiveParameter] array $input, ?ClientContext $client): ResetResult
    {
        ResetInput::assertCodeType($this->container->make(IdentifierNormalizers::class), $type);

        return $this->reset(CodePurpose::PASSWORD_RESET, $type, ResetInput::CODE_KEY, $input, $client);
    }

    /**
     * Take a submission from the limits, attempt the reset inside the timebox,
     * give the slots back for a reset that succeeded, and report a refusal.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @param  string  $proofKey
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     *
     * @throws \Throwable
     */
    private function reset(CodePurpose $purpose, string $type, string $proofKey, #[\SensitiveParameter] array $input, ?ClientContext $client): ResetResult
    {
        $this->validate();

        $context     = new EventContext($this->context->name(), $client ?? $this->context->client());
        $given       = ResetInput::identifier($input, $type);
        $challenge   = $purpose === CodePurpose::PASSWORD_RESET ? ResetInput::secret($input, ResetInput::CHALLENGE_KEY) : '';
        $challengeId = $this->challengeIdOf($challenge);
        $limiter     = $this->container->make(AttemptLimiter::class);
        $reservation = $limiter->acquire(new AttemptSubject($this->context->name(), AttemptFlow::PASSWORD_RESET, $given, $type, $context->client->ip));

        if ($reservation->retryAfter !== null) {
            return $this->refuse(ResetResult::rateLimited($reservation->retryAfter), FailureReason::RATE_LIMITED, $context, $given, $reservation->retryAfter, $challengeId);
        }

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $proof    = new \SensitiveParameterValue(ResetInput::secret($input, $proofKey));
        $password = new \SensitiveParameterValue(ResetInput::secret($input, ResetInput::PASSWORD_KEY));

        $client = $context->client;

        /** @var array{0: \SineMacula\Laravel\Authentication\Passwords\ResetResult, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason} $outcome */
        $outcome = $this->context->timebox()->run(
            fn (Timebox $timebox): array => $this->attempt($purpose, $type, $given, [$challenge, $proof->getValue()], $password->getValue(), $client, $timebox),
        );

        [$result, $reason] = $outcome;

        if ($result->isReset()) {
            $limiter->release($reservation);
        }

        return $reason === null ? $result : $this->refuse($result, $reason, $context, $given, null, $challengeId);
    }

    /**
     * Check the input and the password, find the identity, and spend the proof
     * with the new password; a reset ends the timebox early.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @param  ?string  $given
     * @param  array{0: ?string, 1: ?string}  $proof
     * @param  ?string  $password
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Illuminate\Support\Timebox  $timebox
     * @return array{0: \SineMacula\Laravel\Authentication\Passwords\ResetResult, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}
     *
     * @throws \Throwable
     */
    private function attempt(
        CodePurpose $purpose,
        string $type,
        ?string $given,
        #[\SensitiveParameter] array $proof,
        #[\SensitiveParameter] ?string $password,
        ClientContext $client,
        Timebox $timebox,
    ): array {
        $identifier = $given === null ? null : $this->container->make(IdentifierVerifier::class)->canonical($type, $given);

        [$challenge, $secret] = $proof;

        $wellFormed = $challenge !== null && $secret !== null && $password !== null && $this->isWellFormed($purpose, $challenge, $secret);

        if (!$wellFormed || $identifier === null || $identifier === '') {
            return [ResetResult::invalid(), FailureReason::INVALID_CREDENTIALS];
        }

        $check = (new PasswordPolicy($this->container))->check($password);

        if ($check->violations !== []) {
            return [ResetResult::passwordRejected($check->violations), null];
        }

        $guard   = $this->context->name();
        $binding = $purpose === CodePurpose::PASSWORD_RESET_LINK
            ? CodeBinding::passwordResetLink($guard, $type, $identifier)
            : CodeBinding::passwordReset($guard, $type, $identifier);
        $recipient = ResetRecipient::find($guard, $this->context->provider(), $binding, $this->container);
        $outcome   = $this->spend($binding, [$challenge, $secret], $recipient, $password, $client);

        if ($outcome[0]->isReset()) {
            $timebox->returnEarly();
        }

        return $outcome;
    }

    /**
     * In one transaction on the codes' connection: lock the row of the eligible
     * identity found (see `IdentityLock`) and decide again, on the row as
     * locked, whether it may reset, check the proof, then set its password,
     * committing a refused proof (its attempt counted) and rolling back an
     * accepted one that no eligible identity can use. The identity found is
     * held to the connection rule only once the proof is accepted, so whether
     * the rule refuses it (for a provider whose configuration names no model,
     * which `validate()` cannot check) never says, to someone without a valid
     * proof, that the identifier is held.
     *
     * Inside a caller's transaction a refused proof completes the nested
     * transaction with its attempt counted, which only the caller's commit
     * keeps: its rollback gives the attempt back, and the `password_reset`
     * counts too while `rate_limits.connection` is the storage connection. An
     * accepted proof no identity may use rolls back only the reset's writes; a
     * deadlock or serialisation failure, or on MySQL and MariaDB a lock wait
     * timeout, is thrown on as Laravel's `DeadlockException` with the caller's
     * transaction level restored. On MySQL and MariaDB a deadlock has already
     * rolled the caller's whole transaction back, its savepoints with it; after
     * a lock wait timeout (MySQL rolls back only the statement that timed out)
     * or a serialisation failure that leaves the caller's transaction open,
     * what the reset wrote before it (the password, the spent proof, the
     * cutoff, some of the revocations) may still be in it. So the caller never
     * commits after the exception: it rolls back and retries whole.
     * PostgreSQL's lock timeout is no concurrency error to Laravel: it is
     * thrown as raised, the reset rolled back to its savepoint.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  array{0: string, 1: string}  $proof
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $recipient
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return array{0: \SineMacula\Laravel\Authentication\Passwords\ResetResult, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}
     *
     * @throws \Throwable
     */
    private function spend(
        CodeBinding $binding,
        #[\SensitiveParameter] array $proof,
        FailureReason|(Identity&Model) $recipient,
        #[\SensitiveParameter] string $password,
        ClientContext $client,
    ): array {
        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $heldProof    = new \SensitiveParameterValue($proof);
        $heldPassword = new \SensitiveParameterValue($password);

        try {
            $outcome = (new OneTimeCode)->getConnection()->transaction(function () use ($binding, $heldProof, $recipient, $heldPassword, $client): FailureReason|int {

                $eligible = $recipient instanceof Model
                    ? ResetRecipient::eligible($this->context->name(), IdentityLock::acquire($recipient), $binding, $this->container)
                    : $recipient;

                $check = $this->checkProof($binding, $heldProof->getValue());

                if ($check !== CodeCheck::ACCEPTED) {
                    return self::refusal($binding, $check);
                }

                if ($eligible instanceof FailureReason) {
                    throw new ResetRefused($eligible);
                }

                SharedConnection::assert($eligible, self::FLOW, $this->container->make(Repository::class));

                return (new PasswordWriter($this->context, $this->revocations, $this->container))->write($eligible, $heldPassword->getValue(), PasswordFlow::RESET, null, $client);
            });
        } catch (ResetRefused $refused) {
            return [ResetResult::invalid(), $refused->reason];
        }

        return is_int($outcome) ? [ResetResult::reset($outcome), null] : [ResetResult::invalid(), $outcome];
    }

    /**
     * Check the proof against the binding's live token or code: a token without
     * counting an attempt, a code, for the challenge it names, counting one.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  array{0: string, 1: string}  $proof
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function checkProof(CodeBinding $binding, #[\SensitiveParameter] array $proof): CodeCheck
    {
        $codes = $this->container->make(OneTimeCodes::class);
        $now   = CarbonImmutable::now()->startOfSecond();

        [$challenge, $secret] = $proof;

        return $binding->purpose === CodePurpose::PASSWORD_RESET_LINK ? $codes->checkToken($binding, $secret, $now) : $codes->check($binding, $challenge, $secret, $now);
    }

    /**
     * Whether the proof has the shape of a token, or of a code and the
     * challenge id it names, of the purpose.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $challenge
     * @param  string  $proof
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function isWellFormed(CodePurpose $purpose, string $challenge, #[\SensitiveParameter] string $proof): bool
    {
        $codes = $this->container->make(OneTimeCodes::class);

        return $purpose === CodePurpose::PASSWORD_RESET_LINK
            ? $codes->isWellFormedToken($proof)
            : $codes->isWellFormed($proof) && $codes->isWellFormedChallenge($challenge);
    }

    /**
     * The id of the challenge a code reset answers, when the input names one in
     * the form the engine issues; `null` otherwise, and for a link's reset,
     * which answers none.
     *
     * @param  ?string  $challenge
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function challengeIdOf(?string $challenge): ?string
    {
        return $challenge !== null && $this->container->make(OneTimeCodes::class)->isWellFormedChallenge($challenge) ? $challenge : null;
    }

    /**
     * Validate every setting a reset reads, and refuse an identity model on
     * another connection than the storage connection before anything is
     * counted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function validate(): void
    {
        $config = $this->container->make(Repository::class);

        (new CodeSettings($config))->validate();
        (new CodeKeys($config))->validate();
        (new PasswordPolicy($this->container))->settings();

        SharedConnection::assertForGuard($this->context->name(), self::FLOW, $config);
    }

    /**
     * Report a refused reset with `AuthenticationFailed`, with the id of the
     * challenge a code reset answered, and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\ResetResult  $result
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $given
     * @param  ?int  $retryAfter
     * @param  ?string  $challengeId
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     */
    private function refuse(ResetResult $result, FailureReason $reason, EventContext $context, ?string $given, ?int $retryAfter = null, ?string $challengeId = null): ResetResult
    {
        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::PASSWORD_RESET, $reason, $given, $retryAfter, $challengeId));

        return $result;
    }

    /**
     * Why a refused proof failed, for the event: `link_expired` or
     * `code_expired`, `code_exhausted`, or `invalid_credentials`.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck  $check
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private static function refusal(CodeBinding $binding, CodeCheck $check): FailureReason
    {
        return match ($check) {
            CodeCheck::EXPIRED   => $binding->purpose === CodePurpose::PASSWORD_RESET_LINK ? FailureReason::LINK_EXPIRED : FailureReason::CODE_EXPIRED,
            CodeCheck::EXHAUSTED => FailureReason::CODE_EXHAUSTED,
            default              => FailureReason::INVALID_CREDENTIALS,
        };
    }
}
