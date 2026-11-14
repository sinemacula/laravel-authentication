<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;

/**
 * Unit tests for the default external identity links, which link nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoExternalLinks::class)]
final class NoExternalLinksTest extends TestCase
{
    /**
     * No result is linked, whatever connection, issuer, subject and NameID
     * format it names.
     *
     * @return void
     */
    public function testLinksNothing(): void
    {
        $links = new NoExternalLinks;

        self::assertNull($links->find('connection-7', 'https://idp.example.test', 'subject-1', null));
        self::assertNull($links->find(str_repeat('c', 255), str_repeat('i', 2048), str_repeat('s', 1024), 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'));
    }
}
