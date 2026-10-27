<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Container\Container;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The sign-in policy checks behind `attempt()`: the audience policy, the
 * attempt limits, the password sign-in method inside the credential timebox,
 * the shared admission checks, the pinned device, the password rehash, and the
 * additional-factor policy.
 *
 * The policies are resolved from the container each time they are needed, so
 * the binding in effect then (the application's, or an MFA package's) is the
 * one used, however long the guard has been alive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait SignsInWithCredentials
{
    /**
     * Run an `attempt()` sign-in up to the bind: the audience policy's method
     * check and the attempt limits, then, inside the credential timebox, the
     * password check and everything after it. The slots the attempt took are
     * given back only when it succeeds.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn  $password
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \Throwable
     */
    private function signInWithCredentials(
        PasswordSignIn $password,
        #[\SensitiveParameter] array $credentials,
        ?Principal $principal,
        ?Device $device,
        ClientContext $client,
    ): AdmittedSignIn|RefusedSignIn {
        $audience = self::signInCollaborator(AudiencePolicy::class);

        if (!$audience->allowsMethod($this->name, PasswordSignIn::NAME)) {
            return new RefusedSignIn(SignInFailureReason::METHOD_NOT_ALLOWED);
        }

        $type        = $password->identifierType();
        $limiter     = self::signInCollaborator(AttemptLimiter::class);
        $reservation = $limiter->acquire(new AttemptSubject($this->name, AttemptFlow::SIGN_IN, $password->identifier($credentials), $type, $client->ip));

        if (!$reservation->granted()) {
            return new RefusedSignIn(SignInFailureReason::RATE_LIMITED, retryAfter: $reservation->retryAfter);
        }

        $outcome = $this->timebox->call(function (Timebox $timebox) use ($password, $credentials, $principal, $device, $client, $audience, $type): AdmittedSignIn|RefusedSignIn {

            $user = $password->retrieve($this->provider, $credentials);

            $this->lastRetrievedUser = $user;

            if (!$user instanceof Identity || !$password->accepts($this->provider, $user, $credentials)) {
                return new RefusedSignIn(SignInFailureReason::INVALID_CREDENTIALS);
            }

            $this->fireValidatedEvent($user);

            $outcome = $this->admitVerifiedIdentity(new SignInAdmission($audience), $user, $principal, $device, $type);

            if ($outcome instanceof AdmittedSignIn) {

                $password->rehash($this->provider, $user, $credentials);

                $outcome = $this->refuseIfAFactorIsRequired($outcome, $client);
            }

            if ($outcome instanceof AdmittedSignIn) {
                $timebox->returnEarly();
            }

            return $outcome;
        }, $this->timeboxMicroseconds());

        if ($outcome instanceof AdmittedSignIn) {
            $limiter->release($reservation);
        }

        return $outcome;
    }

    /**
     * Admit an identity whose password was accepted: activity, the principal
     * (the pinned one, or the resolver's default), the audience policy, and the
     * pinned device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission  $admission
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitVerifiedIdentity(
        SignInAdmission $admission,
        Identity $identity,
        ?Principal $principal,
        ?Device $device,
        string $identifierType,
    ): AdmittedSignIn|RefusedSignIn {
        $admitted = $admission->admit(
            $this->name,
            $identity,
            fn (): ?Principal => $principal === null ? $this->resolvePrincipal($identity) : $this->resolvePinnedPrincipal($identity, $principal),
            $principal === null ? SignInFailureReason::PRINCIPAL_UNRESOLVED : SignInFailureReason::PRINCIPAL_MISMATCH,
            $identifierType,
        );

        if ($admitted instanceof RefusedSignIn) {
            return $admitted;
        }

        if ($device === null) {
            return $admitted;
        }

        $resolvedDevice = $this->resolvePinnedDevice($identity, $device);

        return $resolvedDevice === null
            ? RefusedSignIn::after(SignInFailureReason::DEVICE_MISMATCH, $admitted)
            : $admitted->on($resolvedDevice);
    }

    /**
     * Refuse the admitted sign-in when the additional-factor policy asks it for
     * a further factor, which `attempt()` cannot hand out. A pinned device
     * proves nothing about who holds the client, so the policy is never told of
     * one.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     */
    private function refuseIfAFactorIsRequired(AdmittedSignIn $admitted, ClientContext $client): AdmittedSignIn|RefusedSignIn
    {
        $required = self::signInCollaborator(AdditionalFactorPolicy::class)->requiresAdditionalFactor(new AdditionalFactorContext(
            $this->name,
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            PasswordSignIn::NAME,
            $client,
            null,
            null,
            null,
        ));

        return $required ? RefusedSignIn::after(SignInFailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted) : $admitted;
    }

    /**
     * Resolve a sign-in collaborator from the container.
     *
     * @template TCollaborator of object
     *
     * @param  class-string<TCollaborator>  $abstract
     * @return TCollaborator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function signInCollaborator(string $abstract): object
    {
        return Container::getInstance()->make($abstract);
    }
}
