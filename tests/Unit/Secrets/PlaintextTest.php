<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Secrets\Plaintext;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Unit tests for reading a secret handed in either as a `Secret` or as the
 * string a request carried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Plaintext::class)]
final class PlaintextTest extends TestCase
{
    /**
     * A `Secret` is revealed, and a string is taken as it is.
     *
     * @return void
     */
    public function testASecretIsRevealedAndAStringKept(): void
    {
        self::assertSame('handed-in-as-a-secret', Plaintext::of(new Secret('handed-in-as-a-secret')));
        self::assertSame('handed-in-as-a-string', Plaintext::of('handed-in-as-a-string'));
    }
}
