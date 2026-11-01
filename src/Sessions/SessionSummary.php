<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * What a session list shows of one active session: the session's guard, sign-in
 * method and client, where it was created, when it started, where it was last
 * used, when it ends, and whether it is the session the current request is
 * authenticated with.
 *
 * Safe to return to the identity it belongs to as it is: it never holds a
 * refresh digest, the rotation time, the revocation columns, the owner, or the
 * principal the session acts as. `toArray()` and JSON use snake_case keys and
 * ISO-8601 times.
 *
 * @api
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|string|null>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionSummary implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  ?string  $guard
     * @param  ?string  $signInMethod
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\Carbon\CarbonImmutable  $createdAt
     * @param  ?string  $createdIp
     * @param  ?string  $createdUserAgent
     * @param  \Carbon\CarbonImmutable  $signedInAt
     * @param  ?\Carbon\CarbonImmutable  $lastUsedAt
     * @param  ?string  $lastUsedIp
     * @param  ?string  $lastUsedUserAgent
     * @param  \Carbon\CarbonImmutable  $idleExpiresAt
     * @param  \Carbon\CarbonImmutable  $absoluteExpiresAt
     * @param  bool  $current
     */
    public function __construct(

        /** The session's identifier, as tokens carry it in `sid`. */
        public string $id,

        /** The guard the session belongs to. */
        public ?string $guard,

        /** The sign-in method that started the session. */
        public ?string $signInMethod,

        /** The name the client gave itself. */
        public ?string $clientName,

        /** The platform the client reported. */
        public ?string $platform,

        /** When the session was created, when the model records it. */
        public ?CarbonImmutable $createdAt,

        /** The IP address the session was created from. */
        public ?string $createdIp,

        /** The user agent the session was created with. */
        public ?string $createdUserAgent,

        /** When the session started: the sign-in that created it. */
        public CarbonImmutable $signedInAt,

        /** When the session was last used, or `null` when it never was. */
        public ?CarbonImmutable $lastUsedAt,

        /** The IP address the session was last used from. */
        public ?string $lastUsedIp,

        /** The user agent the session was last used with. */
        public ?string $lastUsedUserAgent,

        /** When the session ends unless it is refreshed. */
        public CarbonImmutable $idleExpiresAt,

        /** When the session ends however often it is refreshed. */
        public CarbonImmutable $absoluteExpiresAt,

        /** Whether this is the session the current request is authenticated with. */
        public bool $current,
    ) {}

    /**
     * Summarise a session read with its deadlines.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  bool  $current
     * @return self
     *
     * @throws \LogicException
     */
    public static function of(EloquentSession&Model $session, bool $current): self
    {
        return new self(
            (string) IdentifierCoercion::stringify($session->getSessionIdentifier()),
            $session->getGuard(),
            $session->getSignInMethod(),
            self::text($session, $session->getClientNameName()),
            self::text($session, $session->getPlatformName()),
            self::createdAt($session),
            self::text($session, $session->getCreatedIpName()),
            self::text($session, $session->getCreatedUserAgentName()),
            self::required($session, $session->getSignedInAt(), 'sign-in time'),
            self::immutable($session->getLastUsedAt()),
            self::text($session, $session->getLastUsedIpName()),
            self::text($session, $session->getLastUsedUserAgentName()),
            self::required($session, $session->getIdleExpiresAt(), 'session deadline'),
            self::required($session, $session->getAbsoluteExpiresAt(), 'session deadline'),
            $current,
        );
    }

    /**
     * The summary with snake_case keys and ISO-8601 times.
     *
     * @return array<string, bool|string|null>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'id'                   => $this->id,
            'guard'                => $this->guard,
            'sign_in_method'       => $this->signInMethod,
            'client_name'          => $this->clientName,
            'platform'             => $this->platform,
            'created_at'           => $this->createdAt?->toIso8601String(),
            'created_ip'           => $this->createdIp,
            'created_user_agent'   => $this->createdUserAgent,
            'signed_in_at'         => $this->signedInAt->toIso8601String(),
            'last_used_at'         => $this->lastUsedAt?->toIso8601String(),
            'last_used_ip'         => $this->lastUsedIp,
            'last_used_user_agent' => $this->lastUsedUserAgent,
            'idle_expires_at'      => $this->idleExpiresAt->toIso8601String(),
            'absolute_expires_at'  => $this->absoluteExpiresAt->toIso8601String(),
            'current'              => $this->current,
        ];
    }

    /**
     * The summary as JSON serialises it: the same as `toArray()`.
     *
     * @return array<string, bool|string|null>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * An informational column as a string, `null` when it is empty, not text,
     * or not loaded.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  string  $column
     * @return ?string
     */
    private static function text(Model $session, string $column): ?string
    {
        $value = self::loaded($session, $column);

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * When the session was created, for a model that keeps a creation time.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return ?\Carbon\CarbonImmutable
     */
    private static function createdAt(Model $session): ?CarbonImmutable
    {
        $column = $session->getCreatedAtColumn();
        $value  = $column === null ? null : self::loaded($session, $column);

        return $value instanceof CarbonInterface ? $value->toImmutable() : null;
    }

    /**
     * A column's value, or `null` when it is not loaded: read without asking
     * for a missing attribute, which a model that prevents accessing missing
     * attributes would refuse.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  string  $column
     * @return mixed
     */
    private static function loaded(Model $session, string $column): mixed
    {
        return array_key_exists($column, $session->getAttributes()) ? $session->getAttribute($column) : null;
    }

    /**
     * A time an active session always has: its sign-in time and both deadlines.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  ?\Carbon\CarbonInterface  $time
     * @param  string  $what
     * @return \Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    private static function required(Model $session, ?CarbonInterface $time, string $what): CarbonImmutable
    {
        $message = sprintf('Session %s of %s has no %s to summarise.', IdentifierCoercion::stringify($session->getKey()), $session::class, $what);

        return self::immutable($time) ?? throw new \LogicException($message);
    }

    /**
     * A time as an immutable instance, keeping `null`.
     *
     * @param  ?\Carbon\CarbonInterface  $time
     * @return ?\Carbon\CarbonImmutable
     */
    private static function immutable(?CarbonInterface $time): ?CarbonImmutable
    {
        return $time?->toImmutable();
    }
}
