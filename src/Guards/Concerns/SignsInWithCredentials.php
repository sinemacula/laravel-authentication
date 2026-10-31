<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Container\Container;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\CredentialAttempt;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The sign-in policy checks behind `attempt()`.
 *
 * The steps the session service's `signIn()` takes the same way (the method
 * check, the slots and their give-back, the refusal by an account's own limit)
 * are `CredentialAttempt`'s; the order, the timebox and what runs inside it,
 * the pins and the refusal of a required factor are `attempt()`'s own.
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
     * password check (refused before any lookup when the identifier key holds
     * anything a lookup could not count, and counted against the account the
     * credentials find) and everything after it. The slots the attempt took,
     * the account's included, are given back only when it succeeds.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn  $password
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Throwable
     */
    private function signInWithCredentials(
        PasswordSignIn $password,
        #[\SensitiveParameter] array $credentials,
        ?Principal $principal,
        ?Device $device,
        ClientContext $client,
    ): Admitted|Refused {
        $guard   = $this->context->name();
        $type    = $password->identifierType($guard);
        $subject = new AttemptSubject($guard, AttemptFlow::SIGN_IN, $password->identifier($guard, $credentials), $type, $client->ip);
        $attempt = CredentialAttempt::begin(Container::getInstance(), $subject, PasswordSignIn::NAME);

        if ($attempt instanceof Refused) {
            return $attempt;
        }

        $outcome = $this->context->timebox()->run(
            function (Timebox $timebox) use ($password, $credentials, $principal, $device, $client, $type, $attempt): Admitted|Refused {

                $user = $this->verifyAttemptedCredentials($password, $credentials, $attempt->accounts);

                if ($user === null) {
                    return $attempt->accountRefusal() ?? new Refused(FailureReason::INVALID_CREDENTIALS);
                }

                $this->fireValidatedEvent($user);

                $outcome = $this->admitVerifiedIdentity(new SignInAdmission($attempt->audience), $user, $principal, $device, $type);

                if ($outcome instanceof Admitted) {

                    $password->rehash($this->context->provider(), $user, $credentials);

                    $outcome = $this->refuseIfAFactorIsRequired($outcome, $client);
                }

                if ($outcome instanceof Admitted) {
                    $timebox->returnEarly();
                }

                return $outcome;
            },
        );

        if ($outcome instanceof Admitted) {
            $attempt->release();
        }

        return $outcome;
    }

    /**
     * Return the identity the credentials of an `attempt()` find and whose
     * password they match, or `null`. Credentials whose identifier key holds
     * anything a lookup could not count are never looked up, and an integer
     * there is looked up as the string it is counted as; otherwise the account
     * found is remembered for Laravel's `Failed` event, and its password check
     * is counted against it in the attempt's account slots.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn  $password
     * @param  array<string, mixed>  $credentials
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts  $accounts
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     */
    private function verifyAttemptedCredentials(PasswordSignIn $password, #[\SensitiveParameter] array $credentials, AccountAttempts $accounts): ?Identity
    {
        $lookup = $password->lookupCredentials($this->context->name(), $credentials);

        if ($lookup === null) {
            return null;
        }

        $user = $password->retrieve($this->context->provider(), $lookup);

        $this->lastRetrievedUser = $user;

        return $user instanceof Identity && $password->verifyPassword($accounts, $this->context->provider(), $user, $lookup) ? $user : null;
    }

    /**
     * Admit an identity whose password was accepted: activity, the principal
     * (the pinned one, or the resolver's default), the audience policy, and the
     * pinned device.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\SignInAdmission  $admission
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitVerifiedIdentity(SignInAdmission $admission, Identity $identity, ?Principal $principal, ?Device $device, string $identifierType): Admitted|Refused
    {
        $admitted = $admission->admit(
            $this->context->name(),
            $identity,
            fn (): ?Principal => $principal === null ? $this->resolvePrincipal($identity) : $this->resolvePinnedPrincipal($identity, $principal),
            $principal === null ? FailureReason::PRINCIPAL_UNRESOLVED : FailureReason::PRINCIPAL_MISMATCH,
            $identifierType,
        );

        if ($admitted instanceof Refused) {
            return $admitted;
        }

        if ($device === null) {
            return $admitted;
        }

        $resolvedDevice = $this->resolvePinnedDevice($identity, $admitted->principal, $device);

        return $resolvedDevice === null
            ? Refused::after(FailureReason::DEVICE_MISMATCH, $admitted)
            : $admitted->on($resolvedDevice);
    }

    /**
     * Refuse the admitted sign-in when the additional-factor policy asks it for
     * a further factor, which `attempt()` cannot hand out. A pinned device
     * proves nothing about who holds the client, so the policy is never told of
     * one.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refuseIfAFactorIsRequired(Admitted $admitted, ClientContext $client): Admitted|Refused
    {
        $required = self::signInCollaborator(AdditionalFactorPolicy::class)->requiresAdditionalFactor(new AdditionalFactorContext(
            $this->context->name(),
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            PasswordSignIn::NAME,
            $client,
            null,
            null,
            null,
        ));

        return $required ? Refused::after(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted) : $admitted;
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
