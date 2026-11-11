<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * Writes a delivery of a one-time code to its key's row, or answers why no
 * delivery may be made.
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
     * not; a capped code never outlasts the delivery window.
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
        $first    = $this->first($delivery, $capped);

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
     * Replace the key's row with the delivery, or answer why not, or `null`
     * when the row changed since it was read.
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
        $windowEnds = $row->window_started_at->getTimestamp() + $this->settings->deliveryWindowSeconds();
        $refusal    = $this->refusal($row, $now, $windowEnds, $capped);

        if ($refusal !== null) {
            return $refusal;
        }

        if ($windowEnds <= $now) {
            return $this->rewrite($row, $delivery->window(), $this->first($delivery, $capped));
        }

        $expiresAt = $delivery->now->addSeconds($capped ? min($delivery->ttlSeconds, $windowEnds - $now) : $delivery->ttlSeconds);
        $resendAt  = $this->resendAt($delivery->now, $row->deliveries + 1, $windowEnds, $capped);
        $live      = CodeRows::live($row, $this->settings->maxAttempts(), $delivery->now) instanceof OneTimeCode && CodeRows::isSameContext($row->context, $delivery->context);
        $resent    = $live
            ? $this->rewrite($row, $delivery->resend($row->deliveries, $expiresAt), $delivery->issued($row->challenge_id, $expiresAt, $resendAt), $delivery->now)
            : null;

        return $resent ?? $this->rewrite($row, $delivery->challenge($row->deliveries, $expiresAt), $delivery->issued($delivery->challengeId, $expiresAt, $resendAt));
    }

    /**
     * Why no delivery may be made to the row's key at the second given, or
     * `null` when one may.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  int  $now
     * @param  int  $windowEnds
     * @param  bool  $capped
     * @return ?\SineMacula\Laravel\Authentication\Codes\DeliveryRefusal
     *
     * @throws \InvalidArgumentException
     */
    private function refusal(OneTimeCode $row, int $now, int $windowEnds, bool $capped): ?DeliveryRefusal
    {
        $cooldown = $this->settings->cooldownSeconds();
        $wait     = $row->issued_at->getTimestamp() + $cooldown - $now;

        if ($wait > 0) {
            return DeliveryRefusal::cooldown($wait);
        }

        $left = $windowEnds - $now;

        if ($left > 0 && $row->deliveries >= $this->settings->maxDeliveries()) {
            return DeliveryRefusal::exhausted($left);
        }

        return $capped && $left > 0 && $left < $cooldown ? DeliveryRefusal::cooldown($left) : null;
    }

    /**
     * The code the delivery issues as the first of a new delivery window, for a
     * new challenge.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeDelivery  $delivery
     * @param  bool  $capped
     * @return \SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     */
    private function first(CodeDelivery $delivery, bool $capped): IssuedCode
    {
        $windowEnds = $delivery->now->getTimestamp() + $this->settings->deliveryWindowSeconds();

        return $delivery->issued($delivery->challengeId, $delivery->now->addSeconds($delivery->ttlSeconds), $this->resendAt($delivery->now, 1, $windowEnds, $capped));
    }

    /**
     * When another delivery may be made to the key after one made at the time
     * given, by the rules `refusal()` applies.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $deliveries
     * @param  int  $windowEnds
     * @param  bool  $capped
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function resendAt(CarbonImmutable $now, int $deliveries, int $windowEnds, bool $capped): CarbonImmutable
    {
        $cooldown = $this->settings->cooldownSeconds();
        $next     = $now->getTimestamp() + $cooldown;
        $waits    = $next < $windowEnds && ($deliveries >= $this->settings->maxDeliveries() || ($capped && $windowEnds - $next < $cooldown));

        return $now->addSeconds(($waits ? $windowEnds : $next) - $now->getTimestamp());
    }

    /**
     * Write the delivery's columns over the row, conditional on the issuance
     * read, or answer `null` when the row changed since it was read.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  array<string, mixed>  $columns
     * @param  \SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @param  ?\Carbon\CarbonImmutable  $liveAt
     * @return ?\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    private function rewrite(OneTimeCode $row, array $columns, IssuedCode $issued, ?CarbonImmutable $liveAt = null): ?IssuedCode
    {
        $query = CodeRows::table()->where('id', $row->id)->where('issue_id', $row->issue_id);

        if ($liveAt !== null) {
            $query->whereNull('consumed_at')
                ->where('expires_at', '>', $row->fromDateTime($liveAt))
                ->where('attempts', '<', $this->settings->maxAttempts());
        }

        return $query->update(self::stored($row, $columns)) === 1 ? $issued : null;
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
