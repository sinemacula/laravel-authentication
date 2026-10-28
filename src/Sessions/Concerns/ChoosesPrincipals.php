<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoice;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;
use SineMacula\Laravel\Authentication\Sessions\PrincipalSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;

/**
 * The session service's principal choice and switch.
 *
 * A sign-in (`signIn()`, `start()`) that names no principal, for an identity
 * whose resolver has no default but which may act as one or more principals on
 * this guard, waits for the identity to choose: it hands out a single-use
 * choice token (`PrincipalChoice`), the attempt-limit slots it took stay
 * counted, and `PrincipalChoiceRequired` reports it once committed. `choose()`
 * continues it as the chosen principal, through the same checks and the
 * additional-factor policy as any sign-in.
 *
 * `switchPrincipal()` moves a session, proven by its refresh token, to another
 * principal of the same identity on the same device (see `PrincipalSwitch`);
 * `switchPrincipalFromRequest()` reads that token from the request through the
 * guard's refresh token transport first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ChoosesPrincipals
{
    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService The guard's token service, which a switch parses and issues with. */
    private readonly JwtTokenService $switchTokens;

    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore The guarded switch write and its locking re-read. */
    private readonly RefreshRotationStore $rotations;

    /**
     * The principals the identity may sign in as on this guard, for a choice or
     * a switch screen: the identity's `principals()`, read on the write
     * connection (for an identity that is its own principal, or has no
     * `principals()`, the resolver's default), that are active, act within an
     * active tenant (or none), and are admitted by the guard's audience policy.
     *
     * With an identifier type, the policy must also admit the identity and each
     * principal with it, as it admits a sign-in that used one: a switch screen
     * passes the type the session's device records
     * (`Auth::device()?->getSignInIdentifierType()`), so it lists only the
     * targets the audience policy lets that session switch to.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return list<\SineMacula\Laravel\Authentication\Contracts\Principal>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principals(Identity $identity, ?string $identifierType = null): array
    {
        return $this->admissible($identity, $identifierType)[0];
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
        $live = $this->liveChoice($token, CarbonImmutable::now()->startOfSecond());

        if ($live === null) {
            return null;
        }

        [$pending, , $identity] = $live;

        [$principals] = $this->admissible($identity, $pending->identifier_type);

        return new PrincipalChoice($token, $pending->guard, $identity, $principals, $pending->sign_in_method, CarbonImmutable::instance($pending->expires_at));
    }

    /**
     * Continue the sign-in the choice token holds, as the chosen principal.
     *
     * The choice is used up whatever the outcome, by a delete only one call can
     * make. Then, as for any sign-in: the method must still be allowed, the
     * principal must be the identity's, resolved through the hinted path as the
     * very one named (`principal_mismatch`), and with its tenant active and
     * admitted by the audience policy with the identifier type the sign-in
     * used; the additional-factor policy is asked, and a required factor turns
     * the choice into a pending factor carrying its attempt-limit slots;
     * otherwise the session starts, continuing the device the client proved it
     * holds when the device records the chosen principal, and the slots are
     * given back once committed. Every token that continues no live choice of
     * this guard fails as `pending_invalid`.
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
        $live = $this->liveChoice($token, $now);

        if ($live === null || !PendingSignIns::delete($live[0], $live[1], $now)) {
            return $this->fail(new RefusedSignIn(FailureReason::PENDING_INVALID), null, SignInContext::fromRequest($this->guard->getRequest()), null, []);
        }

        [$pending, , $identity] = $live;

        $context  = PendingSignIns::context($pending, ClientContext::fromRequest($this->guard->getRequest()));
        $method   = $pending->sign_in_method;
        $audience = $this->collaborator(AudiencePolicy::class);
        $resolver = $this->guard->getPrincipalResolver();
        $admitted = $audience->allowsMethod($this->guard->getName(), $method)
            ? (new SignInAdmission($audience))->admit(
                $this->guard->getName(),
                $identity,
                static fn (): ?Principal => PinnedPrincipal::resolve($resolver, $identity, $principal),
                FailureReason::PRINCIPAL_MISMATCH,
                $pending->identifier_type,
            )
            : new RefusedSignIn(FailureReason::METHOD_NOT_ALLOWED, $identity);

        if ($admitted instanceof RefusedSignIn) {
            return $this->fail($admitted, $method, $context, null, []);
        }

        $proven = PendingSignIns::provenDevice($pending, $identity, $admitted->principal);
        $result = $this->establish($admitted, $proven, $method, $pending->identifier_type, $context, $now, $pending->attempt_windows, PendingSignIns::origin($pending));

        if ($result->isSignedIn()) {
            $this->afterCommit->run($pending, function () use ($pending): void {
                $this->giveBack($pending);
            });
        }

        return $result;
    }

    /**
     * Switch the session the refresh token proves to another principal of its
     * identity, on the same device.
     *
     * On success the guard is bound to the session as the new principal
     * (`Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`, no
     * `Login`), and `PrincipalSwitched` follows once the switch is committed on
     * the device's connection; a switch to the principal the device already
     * records rotates the credential like a refresh and reports no switch. A
     * refused switch reports `AuthenticationFailed` (flow `principal_switch`)
     * and leaves the session as it was, unless the token proved a replay, which
     * revokes the device.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    public function switchPrincipal(#[\SensitiveParameter] string $refreshToken, Principal $principal): SwitchResult
    {
        $client = ClientContext::fromRequest($this->guard->getRequest());
        $revoke = function (EloquentDevice&Model $device, CarbonImmutable $now) use ($client): bool {

            $event = new DeviceRevoked(
                new EventContext($device->getGuard(), $client, device: $device, method: $device->getSignInMethod(), fromDevice: true),
                RevocationReason::ROTATION_REUSE,
            );

            return $this->revocations->revoke($device, RevocationReason::ROTATION_REUSE, $now, fn () => $this->dispatch($event));
        };

        $outcome = (new PrincipalSwitch($this->switchTokens, $this->rotations, $this->guard, $client, $principal, $revoke))
            ->switch($refreshToken);

        if ($outcome instanceof AuthenticationFailed) {

            $this->dispatch($outcome);

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
     * `AuthenticationFailed` (flow `principal_switch`), touching no device;
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
        $request   = $this->guard->getRequest();
        $presented = $this->guard->refreshTransport()->read($request);

        if ($presented instanceof PresentedRefreshToken) {
            return $this->switchPrincipal($presented->token, $principal)->withSource($presented->source);
        }

        if ($presented !== null) {

            $context = new EventContext($this->guard->getName(), ClientContext::fromRequest($request));

            $this->dispatch(new AuthenticationFailed($context, AuthenticationFlow::PRINCIPAL_SWITCH, $presented));

            return SwitchResult::failed($presented);
        }

        return null;
    }

    /**
     * Whether a refusal is of a verified identity that only lacks a principal:
     * no principal was named and the resolver has no default.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn  $refused
     * @return bool
     */
    private static function awaitsChoice(RefusedSignIn $refused): bool
    {
        return $refused->reason === FailureReason::PRINCIPAL_UNRESOLVED && $refused->identity !== null;
    }

    /**
     * Hold a verified sign-in that lacks a principal for the identity to choose
     * one, when it has eligible principals: store the choice with the device
     * the client proved it holds for the identity and the attempt-limit slots
     * it took, and report `PrincipalChoiceRequired` once committed. An identity
     * with no eligible principal fails as `principal_unresolved`.
     *
     * The audience policy admits each principal with the identifier type the
     * sign-in used, as it would a sign-in that named one, so a guard that
     * requires a verified identifier lists no principal (not even which there
     * are) to an identity whose identifier is unverified: when it refuses every
     * principal, the sign-in fails with its reason (`identifier_unverified`),
     * with no choice stored or reported.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?list<array<string, string>>  $attemptWindows
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function offerChoice(Identity $identity, string $method, ?string $identifierType, SignInContext $context, ?array $attemptWindows): RefusedSignIn|SignInResult
    {
        $guard = $this->guard->getName();

        [$principals, $refusal] = $this->admissible($identity, $identifierType);

        if ($principals === []) {
            return new RefusedSignIn($refusal ?? FailureReason::PRINCIPAL_UNRESOLVED, $identity);
        }

        $now    = CarbonImmutable::now()->startOfSecond();
        $proven = $context->refreshToken === null ? null : $this->proof->provenDeviceOf($guard, $identity, null, $context->refreshToken);

        [$token, $expiresAt] = $this->pendings->issueChoice($guard, $identity, $proven, $method, $identifierType, $context, $now, $attemptWindows);

        $event = new PrincipalChoiceRequired(new EventContext($guard, $context->client, $identity, device: $proven, method: $method), $expiresAt);

        $this->afterCommit->run(new PendingSignIn, fn () => $this->dispatch($event));

        return SignInResult::principalRequired(new PrincipalChoice($token, $guard, $identity, $principals, $method, $expiresAt));
    }

    /**
     * The eligible principals the audience policy also admits with the
     * identifier type a sign-in used, and its reason for refusing the identity
     * with it, or for the last principal it refused with it, if any. A sign-in
     * that used no identifier is not held to it.
     *
     * Eligibility is that of `principals()`: active, within an active tenant or
     * none, and admitted with no identifier type; a principal that is not
     * eligible is left out without a reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return array{0: list<\SineMacula\Laravel\Authentication\Contracts\Principal>, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admissible(Identity $identity, ?string $identifierType): array
    {
        $guard    = $this->guard->getName();
        $audience = $this->collaborator(AudiencePolicy::class);
        $refusal  = $identifierType === null ? null : $audience->admitIdentifier($guard, $identity, $identifierType);

        if ($refusal !== null) {
            return [[], $refusal];
        }

        $principals = [];

        foreach ($this->candidates($identity) as $principal) {

            if (!$principal instanceof Principal) {
                continue;
            }

            $reason = self::refusalOf($audience, $guard, $identity, $principal, $identifierType);

            if ($reason === null) {
                $principals[] = $principal;
            }

            $refusal = $reason instanceof FailureReason ? $reason : $refusal;
        }

        return [$principals, $refusal];
    }

    /**
     * The principals the identity may act as, before any check: its
     * `principals()` read on the write connection, or, for an identity that is
     * its own principal or has no `principals()`, the resolver's default.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function candidates(Identity $identity): array
    {
        return $identity instanceof HasPrincipals && !$identity instanceof Principal
            ? WriteConnection::during($identity, static fn (): array => WriteConnection::query($identity->principals())->get()->all())
            : [$this->guard->getPrincipalResolver()->resolve($identity)];
    }

    /**
     * Whether the audience policy refuses the principal to the identifier type:
     * `false` when the principal is not eligible at all (inactive, within an
     * inactive tenant, or refused with no identifier type), the policy's reason
     * when it refuses the eligible principal to the type, and `null` when it
     * admits it. The principal is read as stored (`WriteConnection::stored()`):
     * one of a collection is hydrated with lazy loading prevented under
     * Eloquent strict mode, and its tenant, which the checks read, is loaded on
     * purpose.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return false|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private static function refusalOf(AudiencePolicy $audience, string $guard, Identity $identity, Principal $principal, ?string $identifierType): FailureReason|false|null
    {
        return WriteConnection::stored($principal, static function (Principal $stored) use ($audience, $guard, $identity, $identifierType): FailureReason|false|null {

            if (!ActivationPolicy::isPrincipalActive($stored) || $audience->admit($guard, $identity, $stored, null) !== null) {
                return false;
            }

            return $identifierType === null ? null : $audience->admit($guard, $identity, $stored, $identifierType);
        });
    }

    /**
     * The live choice of this guard the token names, with its secret and its
     * identity reloaded through the guard's provider as the very owner it
     * recorded, or `null`.
     *
     * @param  string  $token
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?array{0: \SineMacula\Laravel\Authentication\Models\PendingSignIn, 1: string, 2: \SineMacula\Laravel\Authentication\Contracts\Identity}
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function liveChoice(#[\SensitiveParameter] string $token, CarbonImmutable $now): ?array
    {
        [$pending, $secret] = PendingSignIns::live($this->guard->getName(), $token, $now, PendingSignIn::PRINCIPAL_CHOICE) ?? [null, ''];

        $identity = $pending === null ? null : PendingSignIns::owner($pending, $this->guard->getProvider());

        return $pending === null || $identity === null ? null : [$pending, $secret, $identity];
    }

    /**
     * Bind the guard to the switched session, report the switch once committed
     * when the principal changed, and answer it.
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

        $this->guard->authenticateAs($session->identity, $session->principal, $session->device);

        if ($switched->switched) {

            $event = new PrincipalSwitched(
                new EventContext($this->guard->getName(), $client, $session->identity, $session->principal, $session->tenant, $session->device, $session->method),
                $this->previousPrincipal($session->identity, $switched->previousType, $switched->previousId),
                $switched->previousType,
                $switched->previousId,
            );

            $this->afterCommit->run($session->device, fn () => $this->dispatch($event));
        }

        return SwitchResult::switched(new SignedInSession($session->identity, $session->principal, $session->device, $session->tokens, (string) $session->method, false));
    }

    /**
     * The principal the device recorded before a switch, resolved through the
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
        $principal = $id === null ? null : $this->guard->getPrincipalResolver()->resolve($identity, $id);

        return $principal !== null
            && PrincipalReference::type($principal) === $type
            && IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $id)
            ? $principal
            : null;
    }
}
