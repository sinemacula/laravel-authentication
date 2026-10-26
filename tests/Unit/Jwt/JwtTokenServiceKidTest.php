<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Concerns\InteractsWithJwtTokens;

/**
 * Kid behavioural tests for `JwtTokenService`.
 *
 * Drives the keyring through the token service's public surface to prove the
 * rotation contract: tokens issued under the active kid carry the kid in their
 * JWT header, the service decodes tokens signed under any kid present in its
 * verification map (so old keys stay valid until they expire), and tokens
 * signed under a kid that is not in the verifier's map are rejected.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceKidTest extends JwtTokenServiceTestCase
{
    use InteractsWithJwtTokens;

    /** @var string Secret material for the previous-generation kid. */
    private const string OLD_SECRET = 'old-rotation-secret-with-32-bytes!!';

    /** @var string Secret material for the current-generation kid. */
    private const string NEW_SECRET = 'new-rotation-secret-with-32-bytes!!';

    /** @var string Kid used by the previous-generation key. */
    private const string OLD_KID = '2026-03';

    /** @var string Kid used by the current-generation key. */
    private const string NEW_KID = '2026-04';

    /**
     * Asserts an issued token embeds the active kid in its JWT header. Decodes
     * the header bytes manually so the assertion does not depend on the
     * verifier path.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuedTokenEmbedsActiveKidInHeader(): void
    {
        $service = $this->makeKidService(
            [self::NEW_KID => self::NEW_SECRET],
            self::NEW_KID,
        );

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $service->issueAccessToken($identity, $principal, null);

        self::assertSame(self::NEW_KID, $this->jwtHeader($token)['kid'] ?? null);
    }

    /**
     * Asserts the token service accepts a token signed under an old kid as long
     * as that kid is still present in its verification map. This is the core
     * graceful-rotation contract: live tokens keep working until their `exp`
     * passes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseAcceptsTokenSignedWithOldKidDuringRotation(): void
    {
        $oldOnlyService = $this->makeKidService(
            [self::OLD_KID => self::OLD_SECRET],
            self::OLD_KID,
        );

        $rotatedService = $this->makeKidService(
            [
                self::NEW_KID => self::NEW_SECRET,
                self::OLD_KID => self::OLD_SECRET,
            ],
            self::NEW_KID,
        );

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $oldOnlyService->issueAccessToken($identity, $principal, null);

        $claims = $rotatedService->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('identity-7', $claims[Claims::SUBJECT->value]);
    }

    /**
     * Asserts a token signed under a kid the verifier does not know is rejected
     * - operators who fully retire a kid should see tokens signed under it stop
     * working.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParseRejectsTokenSignedWithRetiredKid(): void
    {
        $retiredOnlyService = $this->makeKidService(
            [self::OLD_KID => self::OLD_SECRET],
            self::OLD_KID,
        );

        $newOnlyService = $this->makeKidService(
            [self::NEW_KID => self::NEW_SECRET],
            self::NEW_KID,
        );

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $retiredOnlyService->issueAccessToken($identity, $principal, null);

        self::assertNull($newOnlyService->parse($token, TokenType::ACCESS));
    }

    /**
     * Asserts the default test service also stamps its kid into every issued
     * token - there is no headerless token shape.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDefaultServiceEmbedsItsKidInHeader(): void
    {
        $service = $this->makeService();

        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $token = $service->issueAccessToken($identity, $principal, null);

        self::assertSame(self::KID, $this->jwtHeader($token)['kid'] ?? null);
    }

    /**
     * Asserts a token signed with valid key material but carrying no `kid`
     * header is rejected, so a headerless token can never verify.
     *
     * @return void
     */
    public function testParseRejectsTokenWithoutKidHeader(): void
    {
        $token = JWT::encode(
            [
                Claims::SUBJECT->value    => 'identity-7',
                Claims::ISSUED_AT->value  => $this->now->getTimestamp(),
                Claims::EXPIRES_AT->value => $this->now->getTimestamp() + 600,
                Claims::TYPE->value       => TokenType::ACCESS->value,
            ],
            self::SECRET,
            self::ALGORITHM,
        );

        self::assertNull($this->makeService()->parse($token, TokenType::ACCESS));
    }

    /**
     * Construct a `JwtTokenService` configured with a keyring built from the
     * supplied map and active kid.
     *
     * @param  array<string, string>  $keys
     * @param  string  $activeKid
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeKidService(array $keys, string $activeKid): JwtTokenService
    {
        return new JwtTokenService(
            JwtKeyring::fromKeyMap($keys, $activeKid, self::ALGORITHM),
            self::ACCESS_TTL_MINUTES,
            self::REFRESH_TTL_MINUTES,
        );
    }
}
