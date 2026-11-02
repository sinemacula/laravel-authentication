<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * Writes a delivery of a one-time code to its key's row, for the engine: the
 * first row of a key, a new delivery window once the last has ended, a resend
 * of the live challenge, or a new challenge in the window; or answers why no
 * delivery may be made (the resend cooldown, or the window's delivery cap).
 *
 * Every write is one statement conditional on the issuance the delivery read,
 * so of concurrent deliveries for one key exactly one is written, and no
 * locking read is made, so a transaction around a first delivery locks no gap
 * of the index.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChallengeDeliveries
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeSettings  $settings
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeKeys  $keys
     */
    public function __construct(

        /** The code settings, read on every call. */
        private CodeSettings $settings,

        /** The keyed digests of bindings and codes. */
        private CodeKeys $keys,
    ) {}

    /**
     * Write the secret as a new delivery for the binding's key, or answer why
     * not and the seconds until another may be: a token's lifetime is its own,
     * a code's (`$capped`) never outlasts the delivery window; a delivery that
     * names a request of its own tries the insert first.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @param  string  $secret
     * @param  int  $ttlSeconds
     * @param  bool  $capped
     * @param  bool  $insertFirst
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function deliver(
        CodeBinding $binding,
        CarbonImmutable $now,
        #[\SensitiveParameter] string $secret,
        int $ttlSeconds,
        bool $capped,
        bool $insertFirst = false,
    ): DeliveryRefusal|IssuedCode {
        $delivery = CodeDelivery::for($this->keys, $binding, $secret, $now, $ttlSeconds);
        $first    = $delivery->issued($delivery->challengeId, $now->addSeconds($ttlSeconds));

        if ($insertFirst && $this->insert($binding, $delivery)) {
            return $first;
        }

        $row = CodeRows::find($delivery->digest);

        if ($row === null) {
            return $this->insert($binding, $delivery) ? $first : $this->wait($delivery->digest, $now);
        }

        return $this->replace($row, $delivery, $capped) ?? $this->wait($delivery->digest, $now);
    }

    /**
     * Replace the key's row with the delivery, after the cooldown since its
     * last delivery: in a new delivery window when its window has ended;
     * otherwise, while the window allows another delivery, as a resend of its
     * live challenge in the same transaction, or else as a new challenge.
     * Answers why no delivery may be made, or `null` when the row changed since
     * it was read.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeDelivery  $delivery
     * @param  bool  $capped
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode|null
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    private function replace(OneTimeCode $row, CodeDelivery $delivery, bool $capped): DeliveryRefusal|IssuedCode|null
    {
        $now        = $delivery->now->getTimestamp();
        $windowEnds = $row->window_started_at->getTimestamp() + $this->settings->maxLifetimeSeconds();
        $refusal    = $this->refusal($row, $now, $windowEnds);

        if ($refusal !== null) {
            return $refusal;
        }

        if ($windowEnds <= $now) {
            return $this->rewrite($row, $delivery, $delivery->window(), $delivery->challengeId, $delivery->now->addSeconds($delivery->ttlSeconds));
        }

        $expiresAt = $delivery->now->addSeconds($capped ? min($delivery->ttlSeconds, $windowEnds - $now) : $delivery->ttlSeconds);
        $live      = CodeRows::live($row, $this->settings->maxAttempts(), $delivery->now) instanceof OneTimeCode && CodeRows::isSameContext($row->context, $delivery->context);
        $resent    = $live ? $this->rewrite($row, $delivery, $delivery->resend($row->deliveries, $expiresAt), $row->challenge_id, $expiresAt, true) : null;

        return $resent ?? $this->rewrite($row, $delivery, $delivery->challenge($row->deliveries, $expiresAt), $delivery->challengeId, $expiresAt);
    }

    /**
     * Why no delivery may be made to the row's key at the second given, or
     * `null` when one may: the cooldown since its last delivery has not passed,
     * or its delivery window, ending at the second given, has not ended and has
     * had all its deliveries.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  int  $now
     * @param  int  $windowEnds
     * @return ?\SineMacula\Laravel\Authentication\Codes\DeliveryRefusal
     *
     * @throws \InvalidArgumentException
     */
    private function refusal(OneTimeCode $row, int $now, int $windowEnds): ?DeliveryRefusal
    {
        $wait = $row->issued_at->getTimestamp() + $this->settings->cooldownSeconds() - $now;

        return match (true) {
            $wait       > 0                                                            => DeliveryRefusal::cooldown($wait),
            $windowEnds > $now && $row->deliveries >= $this->settings->maxDeliveries() => DeliveryRefusal::exhausted($windowEnds - $now),
            default                                                                    => null,
        };
    }

    /**
     * Write the delivery's columns over the row, in one update conditional on
     * the issuance read (and, for a resend, on its challenge still being live),
     * and answer the code issued, or `null` when the row changed since it was
     * read.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeDelivery  $delivery
     * @param  array<string, mixed>  $columns
     * @param  string  $challengeId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  bool  $resend
     * @return ?\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    private function rewrite(OneTimeCode $row, CodeDelivery $delivery, array $columns, string $challengeId, CarbonImmutable $expiresAt, bool $resend = false): ?IssuedCode
    {
        $query = CodeRows::table()->where('id', $row->id)->where('issue_id', $row->issue_id);

        if ($resend) {
            $query->whereNull('consumed_at')
                ->where('expires_at', '>', $row->fromDateTime($delivery->now))
                ->where('attempts', '<', $this->settings->maxAttempts());
        }

        return $query->update(self::stored($row, $columns)) === 1 ? $delivery->issued($challengeId, $expiresAt) : null;
    }

    /**
     * Insert the delivery as the key's first row, unless a concurrent issue
     * inserted it first. Returns whether this one did.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeDelivery  $delivery
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function insert(CodeBinding $binding, CodeDelivery $delivery): bool
    {
        $row = ['id' => $delivery->digest, 'purpose' => $binding->purpose->value, 'guard' => $binding->guard, ...$delivery->window()];

        return CodeRows::table()->insertOrIgnore(self::stored(new OneTimeCode, $row)) === 1;
    }

    /**
     * The answer once a delivery could not be written because a concurrent one
     * was: the seconds, at least 1, left of the cooldown since it.
     *
     * @param  string  $digest
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal
     *
     * @throws \InvalidArgumentException
     */
    private function wait(string $digest, CarbonImmutable $now): DeliveryRefusal
    {
        $current = CodeRows::find($digest);

        return DeliveryRefusal::cooldown($current === null ? 1 : $current->issued_at->getTimestamp() + $this->settings->cooldownSeconds() - $now->getTimestamp());
    }

    /**
     * The delivery's columns as the table stores them: times in the model's
     * format.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $model
     * @param  array<string, mixed>  $columns
     * @return array<string, mixed>
     */
    private static function stored(OneTimeCode $model, array $columns): array
    {
        return array_map(static fn (mixed $value): mixed => $value instanceof CarbonImmutable ? $model->fromDateTime($value) : $value, $columns);
    }
}
