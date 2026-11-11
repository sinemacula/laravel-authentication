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
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Checks the session service makes of what a caller hands it, before anything
 * is signed in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionPreconditions
{
    /** @var string Why a first factor an application describes may not stand for an external provider's. */
    public const string EXTERNAL_FACTOR_MESSAGE = 'A first factor over the external provider channel, or with its `amr` value, is made only by the external sign-in.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse an identity that does not own sessions; a non-human identity is
     * let through for the sign-in's admission to refuse.
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
     * pinned to: the argument or the context's, which must not both name one.
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
     * Refuse a machine credential kind, or `external_provider`, as the method a
     * session is started or reauthenticated under.
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
     * Refuse a first factor only an external identity provider's result may
     * make.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\FirstFactor  $factor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertApplicationFactor(FirstFactor $factor): void
    {
        if ($factor->channel->kind === ChannelKind::EXTERNAL_PROVIDER || in_array(FirstFactor::EXTERNAL_PROVIDER_METHOD, $factor->methods, true)) {
            throw new \InvalidArgumentException(self::EXTERNAL_FACTOR_MESSAGE);
        }
    }

    /**
     * Refuse, as `cross_site_request`, a cookie application's request that
     * would set the refresh cookie from another site.
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
     * refusal; any reason but `pending_invalid` is a caller's error.
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
     * Whether the provider's answer is the very identity the caller verified.
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
     * method may give.
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
