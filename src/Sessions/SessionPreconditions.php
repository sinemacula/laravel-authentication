<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Checks the session service makes of what a caller hands it, before anything
 * is signed in: that a session can be started for the identity at all, which
 * principal a session for an externally verified identity is pinned to, whether
 * the guard's provider returned the very identity that was verified, that a
 * session is never started under a machine credential kind or, outside the
 * external sign-in, under `external_provider`, that a sign-in method refused
 * only as a method may, that a cookie application's request that would set the
 * refresh cookie came from its own site, and what a pending-session action was
 * handed as its credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionPreconditions
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse an identity that does not own sessions: a session is a stored row,
     * and a bearer token names one the guard can only find through the
     * identity's `HasSessions` relation, so its access token would never
     * authenticate. Such a guard is access-only and signs in with `attempt()`.
     * A non-human identity is let through: it has no session at all, and the
     * sign-in's admission refuses it as `machine_identity`, a result rather
     * than a misconfiguration.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertHoldsSessions(Identity $identity): void
    {
        if ($identity instanceof HasSessions || $identity instanceof MachineIdentity) {
            return;
        }

        $message = sprintf(
            'The session service can only start sessions for identities that implement %s; %s does not. '
            . 'Sign this guard\'s identities in with attempt() and issue access tokens instead.',
            HasSessions::class,
            $identity::class,
        );

        throw new \LogicException($message);
    }

    /**
     * The principal a session started for an externally verified identity is
     * pinned to: the one given as the argument or on the context, which must
     * not both name one.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \InvalidArgumentException
     */
    public static function pinnedPrincipal(?Principal $principal, SignInContext $context): ?Principal
    {
        if ($principal === null) {
            return $context->principal;
        }

        if ($context->principal !== null) {
            throw new \InvalidArgumentException('Name the principal to start a session as either as the argument or on the context, not both.');
        }

        return $principal;
    }

    /**
     * Refuse a machine credential kind (`api_key`, `client_credentials`) as the
     * method a session is started or reauthenticated under: an application may
     * list one to allow the credential, but it never signs a session in, and a
     * session recorded under one would pass for that credential. Refuse
     * `external_provider` too: only the external sign-in records a session
     * under it, once the link contract has mapped the provider's result to its
     * identity, so no other path may pass for one.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertSessionMethod(string $method): void
    {
        if (in_array($method, SignInMethodManager::CREDENTIAL_METHODS, true)) {
            throw new \InvalidArgumentException(sprintf('[%s] names a machine credential, not a sign-in method; no session can be started with it.', $method));
        }

        if ($method === SignInMethodManager::EXTERNAL_METHOD) {
            throw new \InvalidArgumentException(sprintf('[%s] is not a sign-in method: only a result an external provider verified signs a session in under it.', $method));
        }
    }

    /**
     * Refuse, as `cross_site_request`, a cookie application's sign-in, start or
     * pending-session action whose client did not come from a page of its own
     * site (`RefreshTokenTransport::isSameSiteClient()`): each would set the
     * refresh cookie, so a cross-site form could otherwise sign the browser
     * into another account. A body application's is never refused: its tokens
     * travel only in the response body, which a cross-site page cannot read.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public static function crossSite(RefreshTokenTransport $transport, ClientContext $client): ?Refused
    {
        return $transport->usesCookie() && !$transport->isSameSiteClient($client) ? new Refused(FailureReason::CROSS_SITE_REQUEST) : null;
    }

    /**
     * The pending credential a pending-session action was handed, or its
     * refusal: `pending_invalid`, the one reason `PendingCredential::extract()`
     * answers, is refused as a credential that names no live pending session
     * is; any other reason is a caller's error (`InvalidArgumentException`),
     * raised before anything is dispatched.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Secrets\Secret|string
     *
     * @throws \InvalidArgumentException
     */
    public static function pendingCredential(#[\SensitiveParameter] FailureReason|Secret|string $credential): Refused|Secret|string
    {
        if (!$credential instanceof FailureReason) {
            return $credential;
        }

        if ($credential !== FailureReason::PENDING_INVALID) {
            throw new \InvalidArgumentException("A pending credential is never refused as `{$credential->value}`: hand in only what `PendingCredential::extract()` answered.");
        }

        return new Refused($credential);
    }

    /**
     * Whether the provider's answer is the very identity the caller verified:
     * the same class with the same auth identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $reloaded
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    public static function isSameIdentity(Identity $reloaded, Identity $identity): bool
    {
        return $reloaded::class === $identity::class && IdentifierCoercion::matches($reloaded->getAuthIdentifier(), $identity->getAuthIdentifier());
    }

    /**
     * The reason a sign-in method refused the input with, which must be one a
     * method may give (`FailureReason::isSignInMethodReason()`): any other is
     * the session service's to decide, so a method that answers with one is
     * misconfigured.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $method
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    public static function methodReason(SignInMethod $method, FailureReason $reason): FailureReason
    {
        if (!$reason->isSignInMethodReason()) {

            $message = sprintf(
                'Sign-in method %s refused a sign-in as `%s`, which only the session service may decide;'
                . ' a method answers `invalid_credentials` or another sign-in method reason.',
                $method::class,
                $reason->value,
            );

            throw new \LogicException($message);
        }

        return $reason;
    }
}
