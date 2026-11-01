<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

/**
 * Normaliser fixture that keeps the identifier as given, so a test can use any
 * UTF-8 identifier unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StubVerbatimNormalizer implements IdentifierNormalizer
{
    /**
     * Keep the identifier as given.
     *
     * @param  string  $identifier
     * @return string
     */
    #[\Override]
    public function normalize(#[\SensitiveParameter] string $identifier): string
    {
        return $identifier;
    }
}
