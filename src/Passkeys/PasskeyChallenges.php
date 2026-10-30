<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;

/**
 * Issues and consumes the challenges of passkey ceremonies.
 *
 * A challenge is written when its options are handed out, with the options
 * themselves (which carry the challenge's 32 random bytes), the ceremony it is
 * for, the guard and relying party, and the identity it is bound to (none for a
 * usernameless sign-in). It lives
 * `authentication.passkeys.challenge_ttl_seconds` (30 to 600, 300 by default).
 * It is consumed by the first response to it, with one conditional delete that
 * only one response can make, before the response is verified, so a response
 * that fails verification has used it up too. Every read is from the write
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyChallenges
{
    /** @var string Configuration key of a challenge's lifetime. */
    private const string TTL_KEY = 'authentication.passkeys.challenge_ttl_seconds';

    /** @var int Lifetime used when the configuration has none, in seconds. */
    private const int DEFAULT_TTL_SECONDS = 300;

    /** @var int Shortest lifetime accepted, in seconds. */
    private const int MIN_TTL_SECONDS = 30;

    /** @var int Longest lifetime accepted, in seconds. */
    private const int MAX_TTL_SECONDS = 600;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the lifetime is read from on every issue. */
        private Repository $config,
    ) {}

    /**
     * Store a challenge for the ceremony's options, bound to the guard, the
     * relying party and the owner (none for a sign-in), and return what the
     * client is handed.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $owner
     * @param  array<string, mixed>  $options
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function issue(ChallengePurpose $purpose, RelyingParty $rp, (Identity&Model)|null $owner, array $options, CarbonImmutable $now): CeremonyOptions
    {
        [$type, $id] = $owner === null ? [null, null] : PasskeyOwner::columns($owner);

        $expiresAt = $now->addSeconds($this->ttlSeconds());
        $challenge = new PasskeyChallenge;

        $challenge->forceFill([
            'id'                   => Str::uuid7()->toString(),
            'purpose'              => $purpose->value,
            'guard'                => $rp->guard,
            'rp_id'                => $rp->id,
            'authenticatable_type' => $type,
            'authenticatable_id'   => $id,
            'options'              => $options,
            'expires_at'           => $expiresAt,
        ])->save();

        return new CeremonyOptions($challenge->id, $options, $expiresAt);
    }

    /**
     * Use up the live challenge of the ceremony, guard, relying party and owner
     * (none for a sign-in) the id names, and return the options it was issued
     * with; `null` for an id that names no such challenge, which a malformed
     * one cannot (no query is made for it), or for a challenge that does not
     * record exactly the ceremony, guard, relying party and owner, whatever the
     * columns' collation counts as equal. Only one call can use a challenge up.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $owner
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    public function consume(string $id, ChallengePurpose $purpose, RelyingParty $rp, (Identity&Model)|null $owner, CarbonImmutable $now): ?array
    {
        if (!Str::isUuid($id)) {
            return null;
        }

        $model     = new PasskeyChallenge;
        $challenge = WriteConnection::query($model->newQuery())->find($id);

        if (!$challenge instanceof PasskeyChallenge) {
            return null;
        }

        [$type, $key] = $owner === null ? [null, null] : PasskeyOwner::columns($owner);

        if (!self::isFor($challenge, $purpose, $rp, $type, $key)) {
            return null;
        }

        $consumed = $model->newQueryWithoutScopes()
            ->toBase()
            ->where($model->getKeyName(), $id)
            ->where('purpose', $purpose->value)
            ->where('guard', $rp->guard)
            ->where('rp_id', $rp->id)
            ->where('authenticatable_type', $type)
            ->where('authenticatable_id', $key)
            ->where('expires_at', '>', $model->fromDateTime($now))
            ->delete();

        return $consumed === 1 ? $challenge->options : null;
    }

    /**
     * The configured lifetime of a challenge, in seconds, read as every issue
     * reads it; `authentication:check` validates it the same way.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlSeconds(): int
    {
        $ttl = $this->config->get(self::TTL_KEY, self::DEFAULT_TTL_SECONDS);

        if (is_string($ttl) && preg_match('/^[1-9][0-9]{0,5}$/D', $ttl) === 1) {
            $ttl = (int) $ttl;
        }

        if (!is_int($ttl) || $ttl < self::MIN_TTL_SECONDS || $ttl > self::MAX_TTL_SECONDS) {
            throw new \InvalidArgumentException(sprintf('%s must be an integer from %d to %d seconds.', self::TTL_KEY, self::MIN_TTL_SECONDS, self::MAX_TTL_SECONDS));
        }

        return $ttl;
    }

    /**
     * Whether the challenge records exactly the ceremony, guard, relying party
     * and owner. The statement that loaded it reads by id alone, and the
     * conditional delete compares under the columns' collation, which may count
     * distinct values, such as guards `api` and `API`, as equal.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PasskeyChallenge  $challenge
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  ?string  $type
     * @param  ?string  $key
     * @return bool
     */
    private static function isFor(PasskeyChallenge $challenge, ChallengePurpose $purpose, RelyingParty $rp, ?string $type, ?string $key): bool
    {
        return [$challenge->purpose, $challenge->guard, $challenge->rp_id, $challenge->authenticatable_type, $challenge->authenticatable_id]
            === [$purpose->value, $rp->guard, $rp->id, $type, $key];
    }
}
