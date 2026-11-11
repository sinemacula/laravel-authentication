<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Provides a default `HasChangeableIdentifiers` implementation on an Eloquent
 * identity, on the columns `ProvidesIdentifierVerification` reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers
 */
trait ProvidesIdentifierChanges
{
    use ProvidesIdentifierVerification;

    /**
     * Replace the identifier with one already proven and record it as verified,
     * when the locked row still holds `$current` byte for byte.
     *
     * @param  string  $type
     * @param  ?string  $current
     * @param  string  $replacement
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @imperative
     */
    public function replaceIdentifier(string $type, ?string $current, string $replacement): bool
    {
        $column = $this->getVerifiedAtName(IdentifierType::assertValid($type));

        $values = $this->getConnection()->transaction(function () use ($type, $current, $replacement, $column): ?array {

            $stored = (array) $this->identityRow()->lockForUpdate()->first([$type]);

            if ($stored === [] || !self::isIdentifier($stored[$type], $current)) {
                return null;
            }

            $values = [$type => $replacement, $column => $this->fromDateTime(Carbon::now())];
            $stamp  = $this->usesTimestamps() ? $this->getUpdatedAtColumn() : null;

            if ($stamp !== null) {
                $values[$stamp] = $values[$column];
            }

            return $this->identityRow()->update($values) === 1 ? $values : null;
        });

        if ($values === null) {
            return false;
        }

        $this->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }

    /**
     * Whether the stored identifier is the one given, byte for byte, `null`
     * matching a `null` or empty column.
     *
     * @param  mixed  $stored
     * @param  ?string  $identifier
     * @return bool
     */
    private static function isIdentifier(mixed $stored, ?string $identifier): bool
    {
        return $identifier === null ? $stored === null || $stored === '' : $stored === $identifier;
    }
}
