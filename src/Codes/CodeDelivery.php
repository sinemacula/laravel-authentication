<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;

/**
 * One delivery the engine is about to write for a key: the secret drawn for it,
 * its new issuance and the hash it is stored as, the new challenge id it takes
 * when it starts a challenge, and the columns each way of writing it sets.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeDelivery
{
    /** @var string The new issuance's id. */
    public string $issueId;

    /** @var string The id a new challenge takes. */
    public string $challengeId;

    /**
     * Constructor.
     *
     * @param  string  $digest
     * @param  ?string  $context
     * @param  string  $hash
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @param  \SineMacula\Laravel\Authentication\Codes\IssuedCode  $secret
     */
    private function __construct(

        /** The digest of the key the delivery is for. */
        public string $digest,

        /** The digest of the transaction the delivery is bound to, or `null`. */
        public ?string $context,

        /** The keyed hash the secret is stored as. */
        public string $hash,

        /** When the delivery is made. */
        public CarbonImmutable $now,

        /** How long the secret works for, at most. */
        public int $ttlSeconds,

        /** The secret and its issuance, before its challenge, expiry and resend time are known. */
        private IssuedCode $secret,
    ) {
        $this->issueId     = $secret->issueId;
        $this->challengeId = $secret->challengeId;
    }

    /**
     * Draw a new issuance and challenge id for the secret, delivered to the key
     * now.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeKeys  $keys
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $secret
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function for(CodeKeys $keys, CodeBinding $binding, #[\SensitiveParameter] string $secret, CarbonImmutable $now, int $ttlSeconds): self
    {
        $digest  = $keys->binding($binding);
        $issueId = Str::uuid()->toString();
        $issued  = new IssuedCode($secret, $issueId, $now->addSeconds($ttlSeconds), Str::uuid()->toString(), $now);

        return new self($digest, $keys->context($binding), $keys->code($digest, $issueId, $secret), $now, $ttlSeconds, $issued);
    }

    /**
     * The columns of a delivery that starts a new delivery window, and a new
     * challenge in it.
     *
     * @return array<string, mixed>
     */
    public function window(): array
    {
        return [
            ...$this->challenge(0, $this->now->addSeconds($this->ttlSeconds)),
            'window_started_at' => $this->now,
        ];
    }

    /**
     * The columns of a delivery that starts a new challenge inside the window,
     * after the deliveries it has had.
     *
     * @param  int  $deliveries
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return array<string, mixed>
     */
    public function challenge(int $deliveries, CarbonImmutable $expiresAt): array
    {
        return [
            'challenge_id' => $this->challengeId,
            'context'      => $this->context,
            'attempts'     => 0,
            'consumed_at'  => null,
            ...$this->resend($deliveries, $expiresAt),
        ];
    }

    /**
     * The columns of a delivery of the live challenge again, after the
     * deliveries the window has had: a new code and issuance, its attempts
     * kept.
     *
     * @param  int  $deliveries
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return array<string, mixed>
     */
    public function resend(int $deliveries, CarbonImmutable $expiresAt): array
    {
        return [
            'issue_id'   => $this->issueId,
            'code_hash'  => $this->hash,
            'deliveries' => $deliveries + 1,
            'issued_at'  => $this->now,
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * The code issued once the delivery is written, for the challenge it was
     * written to, working until the time given, with when another may be
     * delivered to its key.
     *
     * @param  string  $challengeId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \Carbon\CarbonImmutable  $resendAvailableAt
     * @return \SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     */
    public function issued(string $challengeId, CarbonImmutable $expiresAt, CarbonImmutable $resendAvailableAt): IssuedCode
    {
        return new IssuedCode($this->secret->code(), $this->issueId, $expiresAt, $challengeId, $resendAvailableAt);
    }
}
