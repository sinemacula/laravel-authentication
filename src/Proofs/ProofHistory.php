<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * What a session's counting proofs say about its authentication, worked out
 * from the summary rows `SessionProofs::history()` reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofHistory
{
    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  list<array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, additional: bool, accepted: bool, at: \Carbon\CarbonImmutable}>  $rows
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function __construct(

        /** The summary rows, each with the newest time among the proofs it groups. */
        private array $rows,
    ) {}

    /**
     * Whether the session records a counting first factor.
     *
     * @return bool
     */
    public function hasFirstFactor(): bool
    {
        foreach ($this->rows as $row) {
            if ($row['kind'] === ProofKind::FIRST_FACTOR) {
                return true;
            }
        }

        return false;
    }

    /**
     * The newest time of any counting proof, or `null` for a session with none.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function authenticatedAt(): ?CarbonImmutable
    {
        $newest = null;

        foreach ($this->rows as $row) {
            $newest = $newest === null || $row['at']->greaterThan($newest) ? $row['at'] : $newest;
        }

        return $newest;
    }

    /**
     * The session's `amr` values, ordered by time then value so the claim is
     * stable, with `mfa` only when an accepted evaluation reported it.
     *
     * @return list<string>
     */
    public function methods(): array
    {
        $rows = array_filter($this->rows, static fn (array $row): bool => $row['accepted'] || !$row['kind']->isReauthentication());

        usort($rows, static fn (array $one, array $other): int => self::order($one) <=> self::order($other));

        $methods     = [];
        $multifactor = false;

        foreach ($rows as $row) {
            array_push($methods, ...$row['methods']);

            $multifactor = $multifactor || ($row['accepted'] && $row['multifactor']);
        }

        $methods = array_values(array_unique(array_diff($methods, [AuthenticationMethods::MULTIFACTOR])));

        return $multifactor ? [...$methods, AuthenticationMethods::MULTIFACTOR] : $methods;
    }

    /**
     * Whether an accepted evaluation on the session is an additional
     * verification.
     *
     * @return bool
     */
    public function hasAdditionalVerification(): bool
    {
        foreach ($this->rows as $row) {
            if (self::isAdditionalVerification($row)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the session holds an accepted recovery code.
     *
     * @return bool
     */
    public function hasRecoveryCode(): bool
    {
        foreach ($this->rows as $row) {
            if (self::isRecoveryCode($row)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an accepted evaluation on the session reported multifactor
     * authentication.
     *
     * @return bool
     */
    public function isMultifactor(): bool
    {
        foreach ($this->rows as $row) {
            if ($row['accepted'] && $row['multifactor']) {
                return true;
            }
        }

        return false;
    }

    /**
     * The newest time among the proofs that are an additional verification or
     * an accepted recovery code, or `null` for a session with none.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function steppedUpAt(): ?CarbonImmutable
    {
        $newest = null;

        foreach ($this->rows as $row) {
            if (!self::isAdditionalVerification($row) && !self::isRecoveryCode($row)) {
                continue;
            }

            $newest = $newest === null || $row['at']->greaterThan($newest) ? $row['at'] : $newest;
        }

        return $newest;
    }

    /**
     * Whether a row is an accepted additional verification.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, additional: bool, accepted: bool, at: \Carbon\CarbonImmutable}  $row
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function isAdditionalVerification(array $row): bool
    {
        if (!$row['accepted'] || $row['kind'] === ProofKind::RECOVERY_CODE) {
            return false;
        }

        return $row['kind'] === ProofKind::ADDITIONAL_FACTOR || $row['additional'];
    }

    /**
     * Whether a row is an accepted recovery code.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, additional: bool, accepted: bool, at: \Carbon\CarbonImmutable}  $row
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function isRecoveryCode(array $row): bool
    {
        return $row['accepted'] && $row['kind'] === ProofKind::RECOVERY_CODE;
    }

    /**
     * What a row is ordered by: its time, then its values.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, additional: bool, accepted: bool, at: \Carbon\CarbonImmutable}  $row
     * @return array{0: int, 1: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function order(array $row): array
    {
        return [$row['at']->getTimestamp(), implode(' ', $row['methods'])];
    }
}
