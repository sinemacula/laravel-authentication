<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Contracts\Translation\Translator;

/**
 * The messages the package puts in front of a client, and their translation.
 *
 * Each is translated through Laravel's translator with its English text as the
 * JSON key, the text Laravel itself uses for the same response, so the
 * application's `lang/{locale}.json` words it for each locale, and a locale
 * without a translation gets the English text. Everything else the package
 * answers with is a code the application words itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConsumerMessages
{
    /** @var string The message of the package guards' `401`. */
    public const string UNAUTHENTICATED = 'Unauthenticated.';

    /** @var string The message of the package's `429`s. */
    public const string TOO_MANY_ATTEMPTS = 'Too Many Attempts.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Translate the message in the translator's current locale, or keep it as
     * it is when the translator answers with something other than a line: a
     * message that names one of the application's translation files gives the
     * whole file.
     *
     * @param  \Illuminate\Contracts\Translation\Translator  $translator
     * @param  string  $message
     * @return string
     */
    public static function translate(Translator $translator, string $message): string
    {
        $line = $translator->get($message);

        return is_string($line) ? $line : $message;
    }
}
