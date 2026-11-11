<?php

declare(strict_types = 1);

namespace Tests\Unit\Context\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;

/**
 * Unit tests for the `CredentialKind` enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialKind::class)]
final class CredentialKindTest extends TestCase
{
    /**
     * A credential is an access token, an API key or a client credentials
     * token, by stable names.
     *
     * @return void
     */
    public function testACredentialIsAnAccessTokenAnApiKeyOrAClientCredentialsToken(): void
    {
        self::assertSame([CredentialKind::ACCESS_TOKEN, CredentialKind::API_KEY, CredentialKind::CLIENT_CREDENTIALS], CredentialKind::cases());
        self::assertSame(['access_token', 'api_key', 'client_credentials'], array_column(CredentialKind::cases(), 'value'));
    }
}
