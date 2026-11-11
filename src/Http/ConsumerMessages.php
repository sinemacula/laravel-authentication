<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Contracts\Translation\Translator;

/**
 * The messages the package puts in front of a client, and their translation.
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
     * Translate the message in the translator's current locale.
     *
     * A message naming a translation file returns the whole file, so a non-line
     * answer keeps the message.
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
