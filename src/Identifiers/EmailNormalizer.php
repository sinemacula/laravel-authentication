<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Identifiers;

use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

/**
 * The default normalizer for email addresses: surrounding whitespace removed
 * and every letter lower-cased.
 *
 * The whole address is lower-cased, local part included. RFC 5321 lets a mail
 * server treat the local part case-sensitively, but almost none do, and an
 * application that let `Ben@x.com` and `ben@x.com` be two accounts would invite
 * takeover by look-alike sign-up. The value is not otherwise validated: format
 * rules belong to the application's validation, so anything that is valid UTF-8
 * and not blank is accepted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EmailNormalizer implements IdentifierNormalizer
{
    /**
     * Trim and lower-case the address; `null` for invalid UTF-8 or a value that
     * is blank once trimmed.
     *
     * @param  string  $identifier
     * @return ?string
     */
    #[\Override]
    public function normalize(#[\SensitiveParameter] string $identifier): ?string
    {
        if (!mb_check_encoding($identifier, 'UTF-8')) {
            return null;
        }

        $normalized = mb_strtolower(trim($identifier), 'UTF-8');

        return $normalized === '' ? null : $normalized;
    }
}
