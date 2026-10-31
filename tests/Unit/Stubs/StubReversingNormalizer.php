<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

/**
 * Normalizer fixture that reverses the identifier, so a test can tell it was
 * the one applied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StubReversingNormalizer implements IdentifierNormalizer
{
    /**
     * Reverse the identifier.
     *
     * @param  string  $identifier
     * @return string
     */
    #[\Override]
    public function normalize(#[\SensitiveParameter] string $identifier): string
    {
        return strrev($identifier);
    }
}
