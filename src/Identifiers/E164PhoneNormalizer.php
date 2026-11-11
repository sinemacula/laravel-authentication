<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Identifiers;

use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

/**
 * The default normaliser for phone numbers: accepts only a number already in
 * E.164 form, with any surrounding whitespace removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class E164PhoneNormalizer implements IdentifierNormalizer
{
    /**
     * The number trimmed, when it is in E.164 form; otherwise `null`.
     *
     * @param  string  $identifier
     * @return ?string
     */
    #[\Override]
    public function normalize(#[\SensitiveParameter] string $identifier): ?string
    {
        $trimmed = trim($identifier);

        return preg_match('/^\+[1-9]\d{1,14}$/D', $trimmed) === 1 ? $trimmed : null;
    }
}
