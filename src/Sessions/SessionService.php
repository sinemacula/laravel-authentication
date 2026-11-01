<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ProvesSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The session service of a JWT guard: signs in, creates the session, issues the
 * first token pair, and binds the guard, in one call.
 *
 * `signIn()` verifies the input with a sign-in method; `start()` begins a
 * session for an identity something else verified (an external identity
 * provider, say). Either way the application policy must allow the method and
 * admit the identity as its principal, the identity, principal and tenant must
 * be active, and the additional-factor policy must not ask for a further
 * factor. Every sign-in creates a new session, which records the proof of its
 * first factor (and the further factor a completion was given, and the
 * provenance of a session an external provider established) in the same
 * transaction; the access token's `auth_time` and `amr` are derived from those
 * proofs. A client that proves, with its refresh token, that it holds a session
 * of this guard for the same identity and principal has that session revoked
 * (`superseded`) in the same transaction; nothing else is revoked, however
 * alike the IP address or user agent are.
 *
 * The session is established by `SessionEstablishment`, which writes it and
 * schedules what reports it but never binds; the service binds the guard only
 * once that has returned. The principals an identity may choose from, and the
 * choice a sign-in without a default waits on, are `PrincipalChoices`'. The
 * service also refreshes a session through `SessionRefresh`
 * (`RefreshesSessions`), steps a session up and reauthenticates it through
 * `SessionStepUp` and `SessionReauthentication` (`ProvesSessions`), each of
 * which issues a new access token only, lets a session switch the principal it
 * acts as, lists sessions, and signs out, revokes sessions and ends sessions on
 * security changes through `SessionRevocations` (`EndsSessions`), which the
 * guard's `logout()` and password changes use too.
 *
 * Failures are results, not exceptions: Laravel's `Failed` and the package's
 * `AuthenticationFailed` report them. Exceptions are kept for misconfiguration
 * and server errors. The service keeps no state between calls: it runs on the
 * guard's context, reading its provider, resolver, dispatcher and request, and
 * the sign-in policies bound in the container, each time it needs them, and
 * reaches the guard's bound state only through the binding it is given. The
 * auth manager builds one on each call of `Auth::sessions()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionService
{
    use EndsSessions, ProvesSessions, RefreshesSessions;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionEstablishment Takes an admitted sign-in to its session or pending sign-in, never binding. */
    private SessionEstablishment $establishment;

    /** @var \SineMacula\Laravel\Authentication\Sessions\PrincipalChoices The principals an identity may choose, and the choices sign-ins wait on. */
    private PrincipalChoices $choices;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers the report of a switch or a refresh until it commits. */
    private AfterCommit $afterCommit;

    /** @var \SineMacula\Laravel\Authentication\Sessions\PendingSignIns Finds and discards the sign-ins waiting for a further factor. */
    private PendingSignIns $pendings;

    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore The guarded switch write and its locking re-read. */
    private RefreshRotationStore $rotations;

    /** @var \SineMacula\Laravel\Authentication\Sessions\RevocationWriter Revokes the session a switch finds its refresh token replayed on. */
    private RevocationWriter $switchRevocations;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __construct(

        /** The context of the guard whose sessions the service starts. */
        private GuardContext $context,

        /** The guard's bound state, which a sign-in, a switch and a sign-out act on. */
        private GuardBinding $binding,

        /** The guard's token service, which a refresh and a switch parse and issue with. */
        private JwtTokenService $tokens,

        /** Container the sign-in methods and policies are resolved from. */
        private Container $container,

        // Resolver for the session's own connection.
        ConnectionResolverInterface $connections,

        // Returns the current transactions manager, if any, when called.
        \Closure $transactions,
    ) {
        $sessions = new RevocationWriter($connections, $transactions);
        $proof    = new ProvenSessions($tokens);
        $writer   = new SessionWriter($context->name(), $tokens, $connections);

        $this->afterCommit       = new AfterCommit($transactions);
        $this->pendings          = new PendingSignIns($container->make(Repository::class));
        $this->establishment     = new SessionEstablishment($context, $writer, $proof, $this->pendings, $this->afterCommit, $container);
        $this->choices           = new PrincipalChoices($context, $proof, $this->pendings, $this->afterCommit, $container);
        $this->revocations       = new SessionRevocations($context, $sessions, $container);
        $this->refreshes         = new SessionRefresh($context, $binding, new RefreshTokenExchange($tokens, $context, $connections, $transactions), $this->afterCommit, $container);
        $this->switchRevocations = $sessions;
        $this->rotations         = new RefreshRotationStore($connections);

        $issuance = new ProofIssuance($context, $tokens);

        $this->stepUps           = new SessionStepUp($context, $tokens, $issuance, $this->afterCommit);
        $this->reauthentications = new SessionReauthentication($context, $tokens, $issuance, $this->afterCommit, $container);
    }

    /**
     * Sign in with the named sign-in method and the input the client sent.
     *
     * In order: Laravel's `Attempting` (with only the identifier the input
     * names, never the input itself); the application policy must allow the
     * method (`method_not_allowed`, nothing counted); the identifier and the
     * client's IP address must have attempts left (`rate_limited`); then,
     * inside the credential timebox, the method must verify the input (its
     * `FirstFactor` is the session's first proof, timed when it returned) and
     * the identity, principal (the context's, verified, or the resolver's
     * default), tenant and application policy must admit it; a password is
     * rehashed when its hash is outdated; the client's refresh token, if any,
     * is checked as proof of an existing session; a deadline the context
     * supplies that has already passed fails as `session_expired`; the
     * additional-factor policy is asked, and when it requires a further factor
     * the result is a pending sign-in instead of a session; otherwise the
     * session starts. A success gives back the attempt's slots and those the
     * method took on the accounts it checked; a pending sign-in keeps them all
     * until it completes.
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function signIn(string $method, #[\SensitiveParameter] array $input, ?SignInContext $context = null): SignInResult
    {
        $driver = $this->container->make(SignInMethodManager::class)->method($method);
        $context ??= SignInContext::fromRequest($this->context->request());
        $type       = $driver->identifierType($this->context->name());
        $identifier = $driver->identifier($this->context->name(), $input);
        $safe       = $identifier === null ? [] : [$type ?? 'identifier' => $identifier];

        $this->context->dispatch(new Attempting($this->context->name(), $safe, false));

        $subject = new AttemptSubject($this->context->name(), AttemptFlow::SIGN_IN, $identifier, $type, $context->client->ip);
        $outcome = $this->signInWith($driver, $method, $input, $context, $subject);

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, $identifier, $safe) : $outcome;
    }

    /**
     * Start a session for an identity verified outside the guard, such as by an
     * external identity provider, through the named method.
     *
     * The identity is reloaded through the guard's identity provider from the
     * write connection and must come back as the same class and key
     * (`identity_unknown`), so the provider's scopes apply. Then the
     * application policy must allow the method, the identity, principal and
     * tenant must be active and admitted (with no identifier type, so the
     * verified-identifier requirement does not apply), and the
     * additional-factor policy is asked, so a sign-in from outside cannot skip
     * a required factor. No attempt limit or timebox applies: nothing is
     * guessed here.
     *
     * The principal to act as is given here or on the context, not both. The
     * method may not be a machine credential kind (`api_key`,
     * `client_credentials`): those authenticate requests or exchanges, never
     * sessions, and a session recorded under one would pass for a machine
     * credential to everything that reads the method.
     *
     * With a provenance (an external provider verified the identity), the
     * session's first proof is the provider's: the connection as its channel,
     * the private `urn:sinemacula:amr:external_provider` `amr` value, and the
     * provider's authentication time (now, when it gave none or one after now),
     * and the provenance is recorded with the session, which the provider's
     * deadline for its session caps. Without one, the first proof names no
     * channel and no `amr` value, timed now. The provenance is the trusted
     * caller's to give, never built from what a client sent.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function start(Identity $identity, ?Principal $principal, string $method, ?SignInContext $context = null, ?Provenance $provenance = null): SignInResult
    {
        SessionPreconditions::assertSessionMethod($method);

        $context ??= SignInContext::fromRequest($this->context->request());
        $pinned = SessionPreconditions::pinnedPrincipal($principal, $context);
        $now    = CarbonImmutable::now()->startOfSecond();
        $proof  = $provenance === null ? SignInProof::unattested($method, $now) : SignInProof::external($method, $provenance, $now);

        $outcome = $this->startFor($identity, $pinned, $method, $context, $proof);

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, []) : $outcome;
    }

    /**
     * Look up the pending sign-in the token completes, without using it up:
     * `null` when the token names no live pending sign-in of this guard, or its
     * identity or principal no longer resolve as recorded.
     *
     * Code that verifies a further factor calls this first, verifies the factor
     * for the identity and principal it returns, and only then calls
     * `complete()`.
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Sessions\PendingFactor
     *
     * @throws \Throwable
     */
    public function pending(#[\SensitiveParameter] string $token): ?PendingFactor
    {
        $found = $this->pendings->find(
            $this->context->name(),
            $token,
            $this->context->provider(),
            $this->context->resolver(),
            CarbonImmutable::now()->startOfSecond(),
        );

        return $found?->factor;
    }

    /**
     * Complete a pending sign-in once its further factor has been verified, and
     * start its session. A trusted entry point, like `start()`: the caller must
     * have verified the factor for the pending sign-in's identity and
     * principal.
     *
     * The proof the factor's adapter verified is given as `$proof`, and the
     * session records it beside its first factor: it must be an
     * `additional_factor` or a `recovery_code`, made for `sign_in`, accepted by
     * the adapter, made no earlier than the pending sign-in's first factor and
     * no later than now (`proof_invalid`), and bound to the pending sign-in's
     * identity, guard and id (`PendingFactor::$id`; `proof_binding_mismatch`).
     * A completion without one stays a trusted assertion that records only the
     * first factor, so the session's `amr` and freshness never claim the factor
     * the caller verified.
     *
     * The pending sign-in is used up whatever the outcome, by a delete that
     * only one completion can make, and gives the attempt-limit slots its
     * sign-in took back only when the session starts, once the delete is
     * committed on the pending sign-in's connection, and reports a failure to
     * give them back to the exception handler. In the same transaction it is
     * checked again (the sign-in's deadline, if it supplied one, not passed
     * while it waited, the method still allowed, the identity, principal and
     * tenant active, and the application policy admitting them with the
     * identifier type the sign-in used) and a new session is written, replacing
     * the proven session when it is unchanged. The factor policy is not asked
     * again. Every token that does not complete a live pending sign-in of this
     * guard fails as `pending_invalid`.
     *
     * @param  string  $token
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function complete(#[\SensitiveParameter] string $token, ?ProofResult $proof = null): SignInResult
    {
        $now   = CarbonImmutable::now()->startOfSecond();
        $found = $this->pendings->find($this->context->name(), $token, $this->context->provider(), $this->context->resolver(), $now);

        if ($found === null) {
            return $this->fail(new Refused(FailureReason::PENDING_INVALID), null, SignInContext::fromRequest($this->context->request()), null, []);
        }

        $context = PendingSignIns::context($found->pending, $this->context->client());
        $outcome = $this->establishment->complete($found, $context, $now, $proof);

        return $outcome instanceof Refused ? $this->fail($outcome, $found->factor->method, $context, null, []) : $this->bound($outcome);
    }

    /**
     * Use up a pending sign-in without starting a session, as when its further
     * factor was not verified or its choice of principal was abandoned, so its
     * token cannot be tried again. The attempt-limit slots its sign-in took
     * stay counted: each factor guess costs a sign-in attempt. Returns whether
     * the token named a live pending sign-in of this guard, of either kind,
     * which this call used up.
     *
     * A discard is the failure of the sign-in that waited: Laravel's `Failed`
     * and then `AuthenticationFailed` report it as `additional_factor_failed`
     * (`principal_choice_abandoned` for a choice), with the method, the
     * discarding request's client, and the identity when the guard's provider
     * still returns it. A token that discards nothing dispatches nothing.
     *
     * @param  string  $token
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function discard(#[\SensitiveParameter] string $token): bool
    {
        $discarded = $this->pendings->discard($this->context->name(), $token, CarbonImmutable::now()->startOfSecond());

        if ($discarded === null) {
            return false;
        }

        $reason  = $discarded->purpose === PendingSignIn::PRINCIPAL_CHOICE ? FailureReason::PRINCIPAL_CHOICE_ABANDONED : FailureReason::ADDITIONAL_FACTOR_FAILED;
        $refused = new Refused($reason, PendingSignIns::owner($discarded, $this->context->provider()));

        $this->fail($refused, $discarded->sign_in_method, SignInContext::fromRequest($this->context->request()), null, []);

        return true;
    }

    /**
     * The principals the identity may sign in as on this guard, for a choice or
     * a switch screen: the identity's `principals()`, read on the write
     * connection (for an identity that is its own principal, or has no
     * `principals()`, the resolver's default), that are active, act within an
     * active tenant (or none), and are admitted by the application policy.
     *
     * With an identifier type, the policy must also admit the identity and each
     * principal with it, as it admits a sign-in that used one: a switch screen
     * passes the type the session records
     * (`Auth::session()?->getSignInIdentifierType()`), so it lists only the
     * targets the application policy lets that session switch to.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return list<\SineMacula\Laravel\Authentication\Contracts\Principal>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principals(Identity $identity, ?string $identifierType = null): array
    {
        return $this->choices->admissible($identity, $identifierType)[0];
    }

    /**
     * Look up the choice the token continues, without using it up: `null` when
     * the token names no live choice of this guard, or its identity no longer
     * resolves as recorded. The principals are the eligible ones now, admitted
     * with the identifier type the sign-in used, as they were when the choice
     * was offered.
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Sessions\PrincipalChoice
     *
     * @throws \Throwable
     */
    public function choice(#[\SensitiveParameter] string $token): ?PrincipalChoice
    {
        $live = $this->choices->liveChoice($token, CarbonImmutable::now()->startOfSecond());

        if ($live === null) {
            return null;
        }

        [$pending, , $identity] = $live;

        [$principals] = $this->choices->admissible($identity, $pending->identifier_type);

        return new PrincipalChoice($token, $pending->guard, $identity, $principals, $pending->sign_in_method, CarbonImmutable::instance($pending->expires_at));
    }

    /**
     * Continue the sign-in the choice token holds, as the chosen principal.
     *
     * The choice is used up whatever the outcome, by a delete only one call can
     * make. Then, as for any sign-in: the method must still be allowed, the
     * principal must be the identity's, resolved through the hinted path as the
     * very one named (`principal_mismatch`), and with its tenant active and
     * admitted by the application policy with the identifier type the sign-in
     * used; the sign-in's deadline, if it supplied one, must not have passed
     * while it waited (`session_expired`); the additional-factor policy is
     * asked, and a required factor turns the choice into a pending factor
     * carrying its attempt-limit slots; otherwise a new session starts,
     * replacing the session the client proved it holds when that session
     * records the chosen principal, and the slots are given back once
     * committed. Every token that continues no live choice of this guard fails
     * as `pending_invalid`.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function choose(#[\SensitiveParameter] string $token, Principal $principal): SignInResult
    {
        $now  = CarbonImmutable::now()->startOfSecond();
        $live = $this->choices->liveChoice($token, $now);

        if ($live === null || !PendingSignIns::delete($live[0], $live[1], $now)) {
            return $this->fail(new Refused(FailureReason::PENDING_INVALID), null, SignInContext::fromRequest($this->context->request()), null, []);
        }

        [$pending, , $identity] = $live;

        $context  = PendingSignIns::context($pending, $this->context->client());
        $method   = $pending->sign_in_method;
        $policy   = $this->container->make(ApplicationPolicy::class);
        $resolver = $this->context->resolver();
        $admitted = $policy->allowsMethod($this->context->name(), $method)
            ? (new SignInAdmission($policy))->admit(
                $this->context->name(),
                $identity,
                static fn (): ?Principal => PinnedPrincipal::resolve($resolver, $identity, $principal),
                FailureReason::PRINCIPAL_MISMATCH,
                $pending->identifier_type,
            )
            : new Refused(FailureReason::METHOD_NOT_ALLOWED, $identity);

        if ($admitted instanceof Refused) {
            return $this->fail($admitted, $method, $context, null, []);
        }

        $proven  = PendingSignIns::provenSession($pending, $identity, $admitted->principal);
        $proof   = SignInProof::kept($pending);
        $outcome = $this->bound($this->establishment->establish($admitted, $proven, $method, $pending->identifier_type, $context, $proof, $now, $pending->attempt_windows, $pending));

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, []) : $outcome;
    }

    /**
     * Switch the session the refresh token proves to another principal of its
     * identity, in the same session.
     *
     * On success `PrincipalSwitched` is scheduled for once the switch is
     * committed on the session's connection (at once when no transaction is
     * open there, so before the bind), and then the guard is bound to the
     * session as the new principal (`Authenticated`, `PrincipalAssigned`,
     * `SessionAuthenticated`, no `Login`); a bind listener that throws cannot
     * withhold the switch's report. A switch to the principal the session
     * already records rotates the credential like a refresh and reports no
     * switch. A refused switch reports `AuthenticationFailed` (flow
     * `principal_switch`) and leaves the session as it was, unless the token
     * proved a replay, which revokes the session.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    public function switchPrincipal(#[\SensitiveParameter] string $refreshToken, Principal $principal): SwitchResult
    {
        $client = $this->context->client();
        $revoke = function (EloquentSession&Model $record, CarbonImmutable $now) use ($client): bool {

            $event = new SessionRevoked(
                new EventContext($record->getGuard(), $client, session: $record, method: $record->getSignInMethod(), fromSession: true),
                RevocationReason::ROTATION_REUSE,
            );

            return $this->switchRevocations->revoke($record, RevocationReason::ROTATION_REUSE, $now, fn () => $this->context->dispatch($event));
        };

        $outcome = (new PrincipalSwitch($this->tokens, $this->rotations, $this->context, $client, $principal, $revoke))
            ->switch($refreshToken);

        if ($outcome instanceof AuthenticationFailed) {

            $this->context->dispatch($outcome);

            return SwitchResult::failed($outcome->reason, $outcome->retryAfter);
        }

        return $this->switched($outcome, $client);
    }

    /**
     * Switch the session to the principal with the refresh token the request
     * carries, read through the guard's refresh token transport, so it comes
     * from the one source the guard allows and a cookie passes its cross-site
     * checks, as `refreshFromRequest()` reads one.
     *
     * Returns `null`, dispatching nothing, when the request carries no token. A
     * token the transport refuses fails with its reason
     * (`refresh_token_conflict`, `cross_site_request`, `token_invalid`) after
     * `AuthenticationFailed` (flow `principal_switch`), touching no session;
     * otherwise it is `switchPrincipal()`. The result says where the token was
     * read from, so a switch read from the cookie can be answered with one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    public function switchPrincipalFromRequest(Principal $principal): ?SwitchResult
    {
        $request   = $this->context->request();
        $presented = RefreshTokenTransport::forGuard($this->context->name(), $this->container->make(ConfigRepository::class))->read($request);

        if ($presented instanceof PresentedRefreshToken) {
            return $this->switchPrincipal($presented->token, $principal)->withSource($presented->source);
        }

        if ($presented !== null) {

            $context = new EventContext($this->context->name(), ClientContext::fromRequest($request));

            $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::PRINCIPAL_SWITCH, $presented));

            return SwitchResult::failed($presented);
        }

        return null;
    }

    /**
     * Run a sign-in from the application policy's method check to the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(SignInMethod $driver, string $method, #[\SensitiveParameter] array $input, SignInContext $context, AttemptSubject $subject): Refused|SignInResult
    {
        $policy = CredentialAttempt::checkMethod($this->container, $subject->guard, $method);

        if ($policy instanceof Refused) {
            return $policy;
        }

        $attempt = CredentialAttempt::begin($this->container->make(AttemptLimiter::class), $policy, $subject);

        if ($attempt instanceof Refused) {
            return $attempt;
        }

        $request = new SignInRequest($subject->guard, $this->context->provider(), $input, $context->client, $attempt->accounts->reserve(...));

        $verified = $this->context->timebox()->run(
            fn (Timebox $timebox) => $this->verify($driver, $method, $request, $attempt, $context, $subject->identifierType, $timebox),
        );

        return $verified instanceof Refused ? $verified : $this->continueVerified($driver, $method, $input, $context, $subject->identifierType, $attempt, $verified);
    }

    /**
     * Continue a sign-in whose method verified the input: rehash a password
     * whose hash is outdated once its identity is admitted (or only lacks a
     * principal), then start the session, or offer the identity a choice of
     * principal, or answer the admission's refusal; a sign-in that started its
     * session gives its attempt-limit slots back.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @param  array{0: \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused, 1: \SineMacula\Laravel\Authentication\Proofs\SignInProof}  $verified
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function continueVerified(
        SignInMethod $driver,
        string $method,
        #[\SensitiveParameter] array $input,
        SignInContext $context,
        ?string $identifierType,
        CredentialAttempt $attempt,
        array $verified,
    ): Refused|SignInResult {
        [$admitted, $proof] = $verified;

        $identity = $admitted instanceof Admitted || PrincipalChoices::awaitsChoice($admitted) ? $admitted->identity : null;

        if ($identity !== null && $driver instanceof PasswordSignIn) {
            $driver->rehash($this->context->provider(), $identity, $input);
        }

        $windows = $attempt->windows();

        $outcome = match (true) {
            $admitted instanceof Admitted => $this->bound($this->establishment->proceed($admitted, $method, $identifierType, $context, $proof, $windows)),
            $identity !== null            => $this->choices->offerChoice($identity, $method, $identifierType, $context, $proof, $windows),
            default                       => $admitted,
        };

        if ($outcome instanceof SignInResult && $outcome->isSignedIn()) {
            $attempt->release();
        }

        return $outcome;
    }

    /**
     * Verify the request with the sign-in method and admit the identity it
     * proves, cutting the timebox short only for an admitted sign-in or one
     * whose verified identity only lacks a principal to act as. A method that
     * verified the input answers with its admission (or refusal) and the proof
     * of its first factor, timed now; one that did not, with its refusal. A
     * sign-in in which an account the method checked had no attempts left is
     * refused as `account_rate_limited`, with that account's wait, for the
     * failure events (the result still says `invalid_credentials`), even when
     * the method returned an identity regardless: it must not have checked that
     * secret. A method that answers with a reason only the session service may
     * give is misconfigured, and a `LogicException` says so.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifierType
     * @param  \Illuminate\Support\Timebox  $timebox
     * @return array{0: \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused, 1: \SineMacula\Laravel\Authentication\Proofs\SignInProof}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function verify(
        SignInMethod $driver,
        string $method,
        SignInRequest $request,
        CredentialAttempt $attempt,
        SignInContext $context,
        ?string $identifierType,
        Timebox $timebox,
    ): array|Refused {
        $verified = $driver->authenticate($request);
        $refusal  = $attempt->accountRefusal();

        if (!$verified instanceof FirstFactor) {
            return $refusal ?? new Refused(SessionPreconditions::methodReason($driver, $verified));
        }

        $proof   = SignInProof::verified($method, $verified, CarbonImmutable::now());
        $outcome = $refusal ?? $this->admit($verified->identity, $context->principal, $identifierType);

        if ($outcome instanceof Admitted || PrincipalChoices::awaitsChoice($outcome)) {
            $timebox->returnEarly();
        }

        return [$outcome, $proof];
    }

    /**
     * Reload an externally verified identity through the guard's provider,
     * check the method is allowed, and admit it, or offer it a choice of
     * principal when it has no default.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function startFor(Identity $identity, ?Principal $principal, string $method, SignInContext $context, SignInProof $proof): Refused|SignInResult
    {
        $reloaded = $this->context->provider()->retrieveById($identity->getAuthIdentifier());

        if (!$reloaded instanceof Identity || !SessionPreconditions::isSameIdentity($reloaded, $identity)) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN, $identity);
        }

        if (!$this->container->make(ApplicationPolicy::class)->allowsMethod($this->context->name(), $method)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED, $reloaded);
        }

        $admitted = $this->admit($reloaded, $principal, null);

        return match (true) {
            $admitted instanceof Admitted             => $this->bound($this->establishment->proceed($admitted, $method, null, $context, $proof)),
            PrincipalChoices::awaitsChoice($admitted) => $this->choices->offerChoice($reloaded, $method, null, $context, $proof, null),
            default                                   => $admitted,
        };
    }

    /**
     * Admit the identity as the pinned principal, verified like a principal
     * pinned on `attempt()`, or as the resolver's default, once it is known to
     * own sessions.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admit(Identity $identity, ?Principal $pinned, ?string $identifierType): Admitted|Refused
    {
        SessionPreconditions::assertHoldsSessions($identity);

        $resolver = $this->context->resolver();

        return (new SignInAdmission($this->container->make(ApplicationPolicy::class)))->admit(
            $this->context->name(),
            $identity,
            static fn (): ?Principal => $pinned === null ? $resolver->resolve($identity) : PinnedPrincipal::resolve($resolver, $identity, $pinned),
            $pinned === null ? FailureReason::PRINCIPAL_UNRESOLVED : FailureReason::PRINCIPAL_MISMATCH,
            $identifierType,
        );
    }

    /**
     * Bind the guard to the session a sign-in started, once establishment has
     * scheduled what reports it (`Validated`, `Login`, `Authenticated`,
     * `PrincipalAssigned` and `SessionAuthenticated`), and answer the result; a
     * result without a session, and a refusal, bind nothing.
     *
     * @template TResult of \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @param  TResult  $result
     * @return TResult
     */
    private function bound(Refused|SignInResult $result): Refused|SignInResult
    {
        $session = $result instanceof SignInResult ? $result->session : null;

        if ($session !== null) {
            $this->binding->login($session->identity, $session->principal, $session->record);
        }

        return $result;
    }

    /**
     * Report a failed sign-in, with Laravel's `Failed` and then
     * `AuthenticationFailed`, and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  ?string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifier
     * @param  array<string, string>  $credentials
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function fail(Refused $refused, ?string $method, SignInContext $context, ?string $identifier, #[\SensitiveParameter] array $credentials): SignInResult
    {
        $name = $this->context->name();

        $this->context->dispatch(new Failed($name, $refused->identity, $credentials));

        $this->context->dispatch(new AuthenticationFailed(
            new EventContext($name, $context->client, $refused->identity, $refused->principal, $refused->tenant, $refused->session, $method),
            AuthenticationFlow::SIGN_IN,
            $refused->reason,
            $identifier,
            $refused->retryAfter,
        ));

        return SignInResult::failed($refused->reason, $refused->retryAfter);
    }

    /**
     * Report the switch once committed when the principal changed, then bind
     * the guard to the switched session, and answer it. The report is scheduled
     * before the bind, so a bind listener that throws cannot withhold it from
     * the switch it already wrote.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal  $switched
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switched(SwitchedPrincipal $switched, ClientContext $client): SwitchResult
    {
        $session = $switched->session;

        if ($switched->switched) {

            $event = new PrincipalSwitched(
                new EventContext($this->context->name(), $client, $session->identity, $session->principal, $session->tenant, $session->record, $session->method),
                $this->previousPrincipal($session->identity, $switched->previousType, $switched->previousId),
                $switched->previousType,
                $switched->previousId,
            );

            $this->afterCommit->run($session->record, fn () => $this->context->dispatch($event));
        }

        $this->binding->authenticateAs($session->identity, $session->principal, $session->record);

        return SwitchResult::switched(new SignedInSession($session->identity, $session->principal, $session->record, $session->tokens, (string) $session->method));
    }

    /**
     * The principal the session recorded before a switch, resolved through the
     * hinted path when it still comes back as that very principal, else `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $type
     * @param  ?string  $id
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function previousPrincipal(Identity $identity, ?string $type, ?string $id): ?Principal
    {
        $principal = $id === null ? null : $this->context->resolver()->resolve($identity, $id);

        return $principal !== null
            && PrincipalReference::type($principal) === $type
            && IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $id)
            ? $principal
            : null;
    }
}
