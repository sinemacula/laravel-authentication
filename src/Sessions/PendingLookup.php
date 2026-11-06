<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Plaintext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Finds the live pending session of a guard a pending credential names, for the
 * pending-session actions and for any other operation that must prove, under
 * the session's lock, that a credential names one (a passkey registration made
 * on a pending sign-in).
 *
 * A credential is `<session key>.<secret>`. It names a live pending session of
 * the guard only while the session is this guard's, pending, not revoked and
 * not ended (its idle deadline is the credential's expiry), its digest matches
 * the secret (compared in constant time), the guard's provider returns its very
 * owner, and the principal it records, if any, still resolves through the
 * hinted path as that principal of that owner. Anything else is not found,
 * without saying why.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingLookup
{
    /** @var int Longest session key a credential may carry, in characters: the identifier columns' length. */
    private const int KEY_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     */
    public function __construct(

        /** The context of the guard whose pending sessions are found. */
        private GuardContext $context,
    ) {}

    /**
     * The live pending session of the guard the credential names, read on the
     * write connection (locked for update when asked), with its owner reloaded
     * through the guard's provider and the principal it records resolved, or
     * `null`. The secret follows the credential's last `.` (it is base64url,
     * which has none), so a session key may hold one. A credential that cannot
     * name one (no key or secret, or a key longer than any the session can
     * have) is rejected without a query.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $lock
     * @return ?array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\Contracts\Identity, 2: ?\SineMacula\Laravel\Authentication\Contracts\Principal}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function find(#[\SensitiveParameter] Secret|string $credential, CarbonImmutable $now, bool $lock): ?array
    {
        $session  = $this->session($credential, $now, $lock);
        $identity = $session === null ? null : $this->owner($session);

        if ($session === null || $identity === null) {
            return null;
        }

        $principal = $this->principalOf($session, $identity);

        return $principal === false ? null : [$session, $identity, $principal];
    }

    /**
     * The live pending session of the guard the credential names, read on the
     * write connection (locked for update when asked), or `null`. A credential
     * that cannot name one (no key or secret, or a key longer than any the
     * session can have) is rejected without a query.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $lock
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function session(#[\SensitiveParameter] Secret|string $credential, CarbonImmutable $now, bool $lock): (EloquentSession&Model)|null
    {
        $plain  = Plaintext::of($credential);
        $dot    = strrpos($plain, '.');
        $key    = $dot === false ? '' : substr($plain, 0, $dot);
        $secret = $dot === false ? '' : substr($plain, $dot + 1);

        if ($key === '' || $secret === '' || mb_strlen($key) > self::KEY_MAX_LENGTH) {
            return null;
        }

        $session = $lock ? SessionLookup::lock($key) : SessionLookup::find($key);

        return $session !== null && $this->isLive($session, $secret, $now) ? $session : null;
    }

    /**
     * Whether the session is a live pending session of the guard, waiting on
     * something and holding the digest of the secret, read inside
     * `WriteConnection::during()`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $secret
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \LogicException
     */
    private function isLive(EloquentSession&Model $session, #[\SensitiveParameter] string $secret, CarbonImmutable $now): bool
    {
        $guard = $this->context->name();
        $held  = new \SensitiveParameterValue($secret);

        return WriteConnection::during($session, static function () use ($session, $held, $guard, $now): bool {

            if (!RefreshTokenHasher::verify($held->getValue(), $session->getPendingKey() ?? '') || $session->getGuard() !== $guard) {
                return false;
            }

            $waiting = $session->getStatus() === SessionStatus::PENDING && $session->getRequires() !== [];

            return $waiting && $session->getRevokedAt() === null && !SessionDeadlines::hasEnded($session, $now);
        });
    }

    /**
     * The session's owner, reloaded through the guard's provider, when it
     * returns that very owner, active or not.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function owner(EloquentSession&Model $session): ?Identity
    {
        $key      = SessionOwnership::ownerKey($session);
        $identity = $key === null ? null : $this->context->provider()->retrieveById($key);

        return $identity instanceof Identity && SessionOwnership::isOwner($session, $identity) ? $identity : null;
    }

    /**
     * The principal the session records, resolved through the hinted path as
     * that very principal, still the owner's: `null` when it records none, and
     * `false` when the one it records no longer resolves so.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return false|\SineMacula\Laravel\Authentication\Contracts\Principal|null
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function principalOf(EloquentSession&Model $session, Identity $identity): false|Principal|null
    {
        $recorded = IdentifierCoercion::stringify($session->getAttribute(PrincipalReference::columns($session)[1]));

        if ($recorded === null) {
            return null;
        }

        $principal = $this->context->resolver()->resolve($identity, $recorded);

        return $principal instanceof Principal && PrincipalReference::isRecordedOn($session, $principal) && PinnedPrincipal::isOwnedBy($principal, $identity)
            ? $principal
            : false;
    }
}
