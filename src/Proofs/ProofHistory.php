<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * What a session's counting proofs say about its authentication, worked out
 * from the summary rows `SessionProofs::history()` reads: one per kind, set of
 * `amr` values and multifactor report, with the newest time among the proofs it
 * summarises.
 *
 * - `authenticatedAt()` (the token's `auth_time`) is the newest time of any
 *   kind: a step-up refreshes it, and so does either reauthentication.
 * - `methods()` (the token's `amr`) is the values of the first factor, the
 *   further factors and the recovery codes, once each, in the order of their
 *   rows' times and then of their values, so the claim is the same whatever
 *   order the database returns the rows in. A stored `mfa` is dropped, and
 *   `mfa` is added only when a further factor's or a recovery code's accepted
 *   evaluation reported multifactor authentication: it is never worked out from
 *   the values. A reauthentication, of either kind, adds nothing: it renews the
 *   authentication time and nothing else.
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
     * @param  list<array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, at: \Carbon\CarbonImmutable}>  $rows
     */
    public function __construct(

        /** The summary rows: one per kind, `amr` values and multifactor report, with its newest time. */
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
     * The session's `amr` values, as the class describes.
     *
     * @return list<string>
     */
    public function methods(): array
    {
        $rows = array_filter($this->rows, static fn (array $row): bool => !$row['kind']->isReauthentication());

        usort($rows, static fn (array $one, array $other): int => self::order($one) <=> self::order($other));

        $methods     = [];
        $multifactor = false;

        foreach ($rows as $row) {
            array_push($methods, ...$row['methods']);

            $multifactor = $multifactor || ($row['kind']->isAdditional() && $row['multifactor']);
        }

        $methods = array_values(array_unique(array_diff($methods, [AuthenticationMethods::MULTIFACTOR])));

        return $multifactor ? [...$methods, AuthenticationMethods::MULTIFACTOR] : $methods;
    }

    /**
     * What a row is ordered by: its time, then its values.
     *
     * @param  array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, at: \Carbon\CarbonImmutable}  $row
     * @return array{0: int, 1: string}
     */
    private static function order(array $row): array
    {
        return [$row['at']->getTimestamp(), implode(' ', $row['methods'])];
    }
}
