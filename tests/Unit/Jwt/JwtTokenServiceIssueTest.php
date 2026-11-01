<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenProfile;
use Tests\Concerns\InteractsWithJwtTokens;

/**
 * Issuance-side unit tests for `JwtTokenService` - `issueAccessToken()` and
 * `issueRefreshToken()`.
 *
 * Split out of the original `JwtTokenServiceTest` so each class stays focused
 * on a single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
#[CoversClass(TokenProfile::class)]
final class JwtTokenServiceIssueTest extends JwtTokenServiceTestCase
{
    use InteractsWithJwtTokens;

    /**
     * Asserts an issued access token decodes back to exactly the profile's
     * claims for the supplied identity and principal: the issuer, audience and
     * guard, the subject as a person, and an `exp` claim the access lifetime in
     * the future, with `at+jwt` as its header type. A token for a session adds
     * the session and its authentication, which the feature tests assert on
     * sessions the session service started.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenReturnsParseableJwt(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null, null);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('at+jwt', $this->jwtHeader($token)['typ'] ?? null);
        self::assertSame([
            Claims::ISSUER->value       => self::ISSUER,
            Claims::AUDIENCE->value     => self::AUDIENCE,
            Claims::CLIENT_ID->value    => self::GUARD,
            Claims::SUBJECT->value      => 'identity-7',
            Claims::SUBJECT_TYPE->value => 'person',
            Claims::PRINCIPAL->value    => 'principal-3',
            Claims::ISSUED_AT->value    => $this->now->getTimestamp(),
            Claims::EXPIRES_AT->value   => $this->now->getTimestamp() + (self::ACCESS_TTL_MINUTES * 60),
        ], array_diff_key($claims, [Claims::JWT_ID->value => true]));
    }

    /**
     * The tenant the caller's admission loaded is carried in `tenant_id`,
     * stringified; without a tenant the claim is absent.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenCarriesTheTenant(): void
    {
        $service   = $this->makeService();
        $identity  = $this->mockIdentity('identity-7');
        $tenant    = $this->mockTenant(9);
        $principal = $this->principalIn('principal-3', $tenant);

        $tenanted   = $service->parse($service->issueAccessToken($identity, $principal, $tenant, null), TokenType::ACCESS);
        $untenanted = $service->parse($service->issueAccessToken($identity, $principal, null, null), TokenType::ACCESS);

        self::assertIsArray($tenanted);
        self::assertIsArray($untenanted);
        self::assertSame('9', $tenanted[Claims::TENANT_ID->value]);
        self::assertArrayNotHasKey(Claims::TENANT_ID->value, $untenanted);
    }

    /**
     * Rows of `[the principal's own tenant's identifier, or null for none]`:
     * principals the tenant 9 is not the tenant of.
     *
     * @return iterable<string, array{0: ?int}>
     */
    public static function provideForeignTenants(): iterable
    {
        yield from [
            'a principal in no tenant'      => [null],
            'a principal in another tenant' => [10],
        ];
    }

    /**
     * An access token never names a tenant the principal does not act within:
     * one given for a principal in no tenant, or in another, is refused.
     *
     * @param  ?int  $own
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideForeignTenants')]
    public function testIssueAccessTokenRefusesATenantThePrincipalIsNotIn(?int $own): void
    {
        $principal = $this->principalIn('principal-3', $own === null ? null : $this->mockTenant($own));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token naming a tenant the principal does not act within');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $principal, $this->mockTenant(9), null);
    }

    /**
     * Identifier values that cannot be written into a required claim: an
     * unsaved model's `null`, the empty string `parse()` reads as missing, and
     * values that are not scalar.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnusableIdentifiers(): iterable
    {
        yield from [
            'null'         => [null],
            'empty string' => [''],
            'array'        => [['id' => 7]],
            'object'       => [new \stdClass],
        ];
    }

    /**
     * An access token is not issued for a tenant whose identifier cannot become
     * the `tenant_id` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesATenantWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `tenant_id` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), $this->mockTenant($identifier), null);
    }

    /**
     * Every issued access token carries a `jti` claim - the unique token
     * identifier that consumers can layer an external revocation denylist
     * against.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenIncludesJtiClaim(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $first  = $service->parse($service->issueAccessToken($identity, $principal, null, null), TokenType::ACCESS);
        $second = $service->parse($service->issueAccessToken($identity, $principal, null, null), TokenType::ACCESS);

        self::assertIsArray($first);
        self::assertIsArray($second);
        self::assertIsString($first[Claims::JWT_ID->value]);
        self::assertIsString($second[Claims::JWT_ID->value]);
        self::assertNotSame($first[Claims::JWT_ID->value], $second[Claims::JWT_ID->value], 'Each access token should carry a fresh jti.');
    }

    /**
     * An integer identifier returned by `getAuthIdentifier()` is stringified in
     * the `sub` claim per RFC 7519 §4.1.2.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenStringifiesIntegerSubjectClaim(): void
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(42);

        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null, null);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('42', $claims[Claims::SUBJECT->value]);
    }

    /**
     * Asserts issuing an access token without a session produces a token with
     * no `sid`, `auth_time` or `amr`: there is no session to name or to have
     * authenticated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssueAccessTokenWithoutSessionCarriesNoSessionClaims(): void
    {
        $identity  = $this->mockIdentity('identity-7');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueAccessToken($identity, $principal, null, null);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame('person', $claims[Claims::SUBJECT_TYPE->value]);
        self::assertArrayNotHasKey(Claims::SESSION_ID->value, $claims);
        self::assertArrayNotHasKey(Claims::AUTH_TIME->value, $claims);
        self::assertArrayNotHasKey(Claims::AUTHENTICATION_METHODS->value, $claims);
    }

    /**
     * Asserts the refresh-token claims are exactly the issuer, audience and
     * guard, the session identifier, the supplied rotation id (`jti`), and an
     * `exp` claim at the session's idle deadline, with the private
     * `refresh+jwt` as its header type. A refresh token issued without a
     * principal omits `principal`.
     *
     * @return void
     */
    public function testIssueRefreshTokenIncludesSessionAndRotationId(): void
    {
        $session = $this->mockSession('session-42');

        $service = $this->makeService();

        $token  = $service->issueRefreshToken($session, 'opaque-rotation-id');
        $claims = $service->parse($token, TokenType::REFRESH);

        self::assertSame('refresh+jwt', $this->jwtHeader($token)['typ'] ?? null);
        self::assertSame([
            Claims::ISSUER->value     => self::ISSUER,
            Claims::AUDIENCE->value   => self::AUDIENCE,
            Claims::CLIENT_ID->value  => self::GUARD,
            Claims::SESSION_ID->value => 'session-42',
            Claims::JWT_ID->value     => 'opaque-rotation-id',
            Claims::ISSUED_AT->value  => $this->now->getTimestamp(),
            Claims::EXPIRES_AT->value => $this->now->getTimestamp() + (self::REFRESH_TTL_MINUTES * 60),
        ], $claims);
    }

    /**
     * Refresh tokens may carry the active principal identifier so refresh can
     * preserve principal context across rotations.
     *
     * @return void
     */
    public function testIssueRefreshTokenIncludesPrincipalIdWhenSupplied(): void
    {
        $session   = $this->mockSession('session-42');
        $principal = $this->mockPrincipal('principal-3');

        $service = $this->makeService();

        $token  = $service->issueRefreshToken($session, 'opaque-rotation-id', $principal);
        $claims = $service->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertSame('session-42', $claims[Claims::SESSION_ID->value]);
        self::assertSame('opaque-rotation-id', $claims[Claims::JWT_ID->value]);
        self::assertSame('principal-3', $claims[Claims::PRINCIPAL->value]);
    }

    /**
     * An access token is not issued for an identity whose identifier cannot
     * become the `sub` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesAnIdentityWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `sub` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity($identifier), $this->mockPrincipal('principal-3'), null, null);
    }

    /**
     * An access token is not issued for a principal whose identifier cannot
     * become the `principal` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesAPrincipalWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `principal` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal($identifier), null, null);
    }

    /**
     * An access token issued with a session whose identifier cannot become the
     * `sid` claim is refused rather than silently issued as session-less.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueAccessTokenRefusesASessionWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `sid` claim');

        $this->makeService()->issueAccessToken($this->mockIdentity('identity-7'), $this->mockPrincipal('principal-3'), null, $this->mockSession($identifier));
    }

    /**
     * A refresh token is not issued for a session whose identifier cannot
     * become the `sid` claim, since `parse()` would reject the token.
     *
     * @param  mixed  $identifier
     * @return void
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueRefreshTokenRefusesASessionWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `sid` claim');

        $this->makeService()->issueRefreshToken($this->mockSession($identifier), 'opaque-rotation-id');
    }

    /**
     * A refresh token issued with a principal whose identifier cannot become
     * the `principal` claim is refused rather than silently issued without one,
     * which would refresh into the default principal.
     *
     * @param  mixed  $identifier
     * @return void
     */
    #[DataProvider('provideUnusableIdentifiers')]
    public function testIssueRefreshTokenRefusesAPrincipalWithoutUsableIdentifier(mixed $identifier): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `principal` claim');

        $this->makeService()->issueRefreshToken($this->mockSession('session-42'), 'opaque-rotation-id', $this->mockPrincipal($identifier));
    }

    /**
     * A refresh token is not issued with an empty rotation id, which would
     * leave the `jti` claim `parse()` requires empty.
     *
     * @return void
     */
    public function testIssueRefreshTokenRefusesAnEmptyRotationId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('without its `jti` claim');

        $this->makeService()->issueRefreshToken($this->mockSession('session-42'), '');
    }

    /**
     * A Tenant mock whose getTenantIdentifier() returns the supplied value.
     *
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private function mockTenant(mixed $id): Tenant
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant $tenant */
        $tenant = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn($id);

        return $tenant;
    }

    /**
     * A principal mock that acts within the tenant given, or in none.
     *
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principalIn(string $id, ?Tenant $tenant): Principal
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn($id);
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        return $principal;
    }
}
