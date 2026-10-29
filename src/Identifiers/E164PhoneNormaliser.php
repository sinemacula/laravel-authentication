<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Identifiers;

use SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser;

/**
 * The default normaliser for phone numbers: accepts only a number already in
 * E.164 form (`+`, a country code that does not start with 0, and at most 15
 * digits in all), with any surrounding whitespace removed.
 *
 * It does not parse numbers: spaces, dashes, brackets, a national format or a
 * leading `00` are refused rather than guessed at, since turning a number a
 * person types into E.164 depends on their country and on numbering plans that
 * change. An application that accepts mobile or free-form numbers binds a
 * normaliser of its own under `phone` in `authentication.identifiers`, backed
 * by `giggsey/libphonenumber-for-php` (suggested in `composer.json`, not
 * required), which returns the E.164 form or `null`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class E164PhoneNormaliser implements IdentifierNormaliser
{
    /**
     * The number trimmed, when it is in E.164 form; otherwise `null`.
     *
     * @param  string  $identifier
     * @return ?string
     */
    #[\Override]
    public function normalise(#[\SensitiveParameter] string $identifier): ?string
    {
        $trimmed = trim($identifier);

        return preg_match('/^\+[1-9]\d{1,14}$/D', $trimmed) === 1 ? $trimmed : null;
    }
}
