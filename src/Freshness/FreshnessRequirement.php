<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * How fresh a session's authentication must be for an operation.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FreshnessRequirement
{
    /** @var int Longest maximum age, in seconds: a day. */
    public const int MAX_AGE_SECONDS = 86400;

    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The proof kinds that count, each once. */
    public array $proofs;

    /**
     * Constructor.
     *
     * @param  int  $maxAgeSeconds
     * @param  array<array-key, mixed>  $proofs
     * @param  bool  $multifactor
     * @param  bool  $phishingResistant
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** How recently a proof that counts must have been made, in seconds, from 1 to a day. */
        public int $maxAgeSeconds,

        // The proof kinds that count: at least one, each once.
        array $proofs,

        /** Whether the proof's evaluation must have reported multifactor authentication. */
        public bool $multifactor = false,

        /** Whether the proof must have been observed to resist phishing. */
        public bool $phishingResistant = false,
    ) {
        if ($maxAgeSeconds < 1 || $maxAgeSeconds > self::MAX_AGE_SECONDS) {
            throw new \InvalidArgumentException(sprintf('A freshness requirement\'s maximum age must be from 1 to %d seconds.', self::MAX_AGE_SECONDS));
        }

        $this->proofs = self::kinds($proofs);
    }

    /**
     * A requirement of a maximum age alone, taking every proof kind.
     *
     * @param  int  $maxAgeSeconds
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function within(int $maxAgeSeconds): self
    {
        return new self($maxAgeSeconds, ProofKind::cases());
    }

    /**
     * The stricter of this requirement and the other, or `null` when they take
     * no kind in common.
     *
     * @param  self  $other
     * @return ?self
     */
    public function stricter(self $other): ?self
    {
        $kinds = array_values(array_filter($this->proofs, static fn (ProofKind $kind): bool => in_array($kind, $other->proofs, true)));

        return $kinds === [] ? null : new self(
            min($this->maxAgeSeconds, $other->maxAgeSeconds),
            $kinds,
            $this->multifactor       || $other->multifactor,
            $this->phishingResistant || $other->phishingResistant,
        );
    }

    /**
     * Whether a proof of the kind counts.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @return bool
     */
    public function takes(ProofKind $kind): bool
    {
        return in_array($kind, $this->proofs, true);
    }

    /**
     * The proof kinds, once they are known to be a non-empty list of distinct
     * kinds.
     *
     * @param  array<array-key, mixed>  $proofs
     * @return list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>
     *
     * @throws \InvalidArgumentException
     */
    private static function kinds(array $proofs): array
    {
        $kinds = array_values(array_filter($proofs, static fn (mixed $kind): bool => $kind instanceof ProofKind));

        if ($proofs === [] || !array_is_list($proofs) || count($kinds) !== count($proofs) || count(array_unique(array_column($kinds, 'value'))) !== count($kinds)) {
            throw new \InvalidArgumentException('A freshness requirement must take a list of distinct proof kinds, at least one.');
        }

        return $kinds;
    }
}
