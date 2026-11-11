<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

/**
 * Makes text a client supplied safe to store in a UTF-8 text column and to show
 * back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClientText
{
    /** @var string The C0 controls, DEL, the C1 controls, and the bidirectional marks, embeddings, overrides and isolates. */
    private const string REMOVED = '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Clean the value for a column of the given length, or `null` when nothing
     * is left.
     *
     * @param  ?string  $value
     * @param  int  $maxLength
     * @return ?string
     */
    public static function clean(?string $value, int $maxLength): ?string
    {
        if ($value === null) {
            return null;
        }

        $visible = preg_replace(self::REMOVED, '', mb_scrub($value, 'UTF-8')) ?? '';
        $cleaned = mb_substr($visible, 0, $maxLength, 'UTF-8');

        return $cleaned === '' ? null : $cleaned;
    }
}
