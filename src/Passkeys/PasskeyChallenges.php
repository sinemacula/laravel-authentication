<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengeRefusal;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Issues and consumes the challenges of passkey ceremonies.
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
     * Store a challenge for the ceremony's options and return what the client
     * is handed.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $owner
     * @param  array<string, mixed>  $options
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function issue(
        ChallengePurpose $purpose,
        RelyingParty $rp,
        (Identity&Model)|null $owner,
        array $options,
        CarbonImmutable $now,
        ?ProofBinding $binding = null,
    ): CeremonyOptions {
        [$type, $id]          = $owner === null ? [null, null] : PasskeyOwner::columns($owner);
        [$session, $boundFor] = self::bindingColumns($binding);

        $expiresAt = $now->addSeconds($this->ttlSeconds());
        $challenge = new PasskeyChallenge;

        $challenge->forceFill([
            'id'                   => Str::uuid7()->toString(),
            'purpose'              => $purpose->value,
            'guard'                => $rp->guard,
            'rp_id'                => $rp->id,
            'authenticatable_type' => $type,
            'authenticatable_id'   => $id,
            'session_id'           => $session,
            'binding_purpose'      => $boundFor,
            'options'              => $options,
            'expires_at'           => $expiresAt,
        ])->save();

        return new CeremonyOptions($challenge->id, $options, $expiresAt);
    }

    /**
     * Use up the challenge the id names and return it, or why it cannot be
     * used.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $owner
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Models\PasskeyChallenge|\SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengeRefusal
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    public function consume(
        string $id,
        ChallengePurpose $purpose,
        RelyingParty $rp,
        (Identity&Model)|null $owner,
        CarbonImmutable $now,
        ?ProofBinding $binding = null,
    ): ChallengeRefusal|PasskeyChallenge {
        if (!Str::isUuid($id)) {
            return ChallengeRefusal::NOT_FOUND;
        }

        $model     = new PasskeyChallenge;
        $challenge = WriteConnection::query($model->newQuery())->find($id);

        if (!$challenge instanceof PasskeyChallenge) {
            return ChallengeRefusal::NOT_FOUND;
        }

        [$type, $key] = $owner === null ? [null, null] : PasskeyOwner::columns($owner);

        $bound = $binding === null || self::bindingColumns($binding) === [$challenge->session_id, $challenge->binding_purpose];

        if (!$bound || !self::isFor($challenge, $purpose, $rp, $type, $key)) {
            return ChallengeRefusal::NOT_FOUND;
        }

        if ($challenge->consumed_at !== null) {
            return ChallengeRefusal::USED;
        }

        if ($challenge->expires_at->lessThanOrEqualTo($now)) {
            return ChallengeRefusal::EXPIRED;
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
            ->whereNull('consumed_at')
            ->update(['consumed_at' => $model->fromDateTime($now)]);

        return $consumed === 1 ? $challenge : ChallengeRefusal::USED;
    }

    /**
     * The binding the challenge records, or `null` for none.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PasskeyChallenge  $challenge
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding
     *
     * @throws \InvalidArgumentException
     * @throws \ValueError
     */
    public static function bindingOf(PasskeyChallenge $challenge, Identity $identity): ?ProofBinding
    {
        return $challenge->binding_purpose === null ? null : new ProofBinding($identity, $challenge->guard, $challenge->session_id, Purpose::from($challenge->binding_purpose));
    }

    /**
     * The configured lifetime of a challenge, in seconds.
     *
     * @return positive-int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlSeconds(): int
    {
        return IntegerSetting::read($this->config, self::TTL_KEY, self::DEFAULT_TTL_SECONDS, self::MIN_TTL_SECONDS, self::MAX_TTL_SECONDS);
    }

    /**
     * Whether the challenge records exactly the ceremony, guard, relying party
     * and owner, whatever the columns' collation counts as equal.
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

    /**
     * The session key and purpose a binding records, or neither for none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return array{0: ?string, 1: ?string}
     */
    private static function bindingColumns(?ProofBinding $binding): array
    {
        return $binding === null ? [null, null] : [IdentifierCoercion::stringify($binding->sessionId), $binding->purpose->value];
    }
}
