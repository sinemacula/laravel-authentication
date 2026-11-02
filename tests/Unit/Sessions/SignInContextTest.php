<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Unit tests for the context of a sign-in: the client description it cleans,
 * and what it carries through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInContext::class)]
final class SignInContextTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of `[given, stored]`: client descriptions and what is kept of them.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideDescriptions(): iterable
    {
        yield from [
            'absent'                         => [null, null],
            'empty'                          => ['', null],
            'only a NUL byte'                => ["\0", null],
            'plain'                          => ['Work laptop', 'Work laptop'],
            'NUL bytes removed'              => ["Work\0 laptop\0", 'Work laptop'],
            'invalid UTF-8 replaced'         => ["Lap \xC3\x28 \xFF", 'Lap ?( ?'],
            'whitespace kept'                => ['  spaced  ', '  spaced  '],
            '255 characters kept'            => [str_repeat('é', 255), str_repeat('é', 255)],
            'cut to 255 characters'          => [str_repeat('é', 256), str_repeat('é', 255)],
            'cut after cleaning, not before' => ["\0" . str_repeat('a', 255) . 'b', str_repeat('a', 255)],
        ];
    }

    /**
     * The client name and platform are made safe to store: NUL bytes removed,
     * invalid UTF-8 replaced, cut to 255 characters, and empty read as `null`.
     *
     * @param  ?string  $given
     * @param  ?string  $stored
     * @return void
     */
    #[DataProvider('provideDescriptions')]
    public function testTheClientDescriptionIsCleaned(?string $given, ?string $stored): void
    {
        $context = new SignInContext(new ClientContext(null, null), $given, $given);

        self::assertSame($stored, $context->clientName);
        self::assertSame($stored, $context->platform);
    }

    /**
     * The client, the principal and the refresh token are carried as given, and
     * default to none.
     *
     * @return void
     */
    public function testCarriesTheClientPrincipalAndRefreshToken(): void
    {
        $client    = new ClientContext('203.0.113.7', 'agent');
        $principal = \Mockery::mock(Principal::class);
        $context   = new SignInContext($client, principal: $principal, refreshToken: 'refresh-token');

        self::assertSame($client, $context->client);
        self::assertSame($principal, $context->principal);
        self::assertSame('refresh-token', $context->refreshToken?->reveal());

        $bare = new SignInContext($client);

        self::assertNull($bare->clientName);
        self::assertNull($bare->platform);
        self::assertNull($bare->principal);
        self::assertNull($bare->refreshToken);
        self::assertNull($bare->notAfter);
        self::assertNull($bare->tenant);
    }

    /**
     * The tenant a sign-in asks to act in is carried as given, through a capped
     * deadline too, and through the request's context when the application
     * passes it; the request itself never supplies one.
     *
     * @return void
     */
    public function testCarriesTheTenantTheSignInAsksFor(): void
    {
        $tenant  = TenantSelection::of('tenant-7');
        $context = new SignInContext(new ClientContext(null, null), tenant: $tenant);
        $request = Request::create('/sign-in', 'POST', ['tenant' => 'tenant-9']);

        self::assertSame($tenant, $context->tenant);
        self::assertSame($tenant, $context->withNotAfter(CarbonImmutable::now())->tenant);
        self::assertSame($tenant, SignInContext::fromRequest($request, tenant: $tenant)->tenant);
        self::assertNull(SignInContext::fromRequest($request)->tenant);
    }

    /**
     * The deadline is kept as an immutable time cut to the whole second, in the
     * timezone it was given in.
     *
     * @return void
     */
    public function testTheDeadlineIsCutToTheWholeSecond(): void
    {
        $context = new SignInContext(new ClientContext(null, null), notAfter: CarbonImmutable::parse('2026-04-06 12:00:00.900000', 'Europe/London'));

        self::assertNotNull($context->notAfter);
        self::assertSame('2026-04-06 12:00:00.000000', $context->notAfter->format('Y-m-d H:i:s.u'));
        self::assertSame('Europe/London', $context->notAfter->getTimezone()->getName());
    }

    /**
     * Rows of `[seconds from now to the context's deadline or null, seconds
     * from now to the deadline given or null, seconds from now to the deadline
     * kept or null]`.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: ?int}>
     */
    public static function provideDeadlines(): iterable
    {
        yield from [
            'neither'                   => [null, null, null],
            'the context alone'         => [60, null, 60],
            'the given alone'           => [null, 60, 60],
            'the given earlier'         => [60, 30, 30],
            'the context earlier'       => [30, 60, 30],
            'both the same second'      => [60, 60, 60],
            'the given one second less' => [60, 59, 59],
        ];
    }

    /**
     * `withNotAfter()` keeps the earlier of the context's deadline and the one
     * given, either alone when the other is absent, and none for neither, so it
     * only ever lowers a deadline; the rest of the context is kept.
     *
     * @param  ?int  $contextIn
     * @param  ?int  $givenIn
     * @param  ?int  $keptIn
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testWithNotAfterKeepsTheEarlierDeadline(?int $contextIn, ?int $givenIn, ?int $keptIn): void
    {
        $now       = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $client    = new ClientContext('203.0.113.7', 'agent');
        $principal = \Mockery::mock(Principal::class);
        $context   = new SignInContext($client, 'Laptop', 'macOS', $principal, 'refresh-token', $contextIn === null ? null : $now->addSeconds($contextIn));
        $capped    = $context->withNotAfter($givenIn === null ? null : $now->addSeconds($givenIn)->addMilliseconds(500));

        self::assertSame($keptIn === null ? null : $now->getTimestamp() + $keptIn, $capped->notAfter?->getTimestamp());
        self::assertSame(
            [$client, 'Laptop', 'macOS', $principal, $context->refreshToken],
            [$capped->client, $capped->clientName, $capped->platform, $capped->principal, $capped->refreshToken],
        );
        self::assertSame($contextIn === null ? null : $now->getTimestamp() + $contextIn, $context->notAfter?->getTimestamp());
    }

    /**
     * Of two deadlines in the same second, the context keeps its own.
     *
     * @return void
     */
    public function testWithNotAfterKeepsItsOwnDeadlineForTheSameSecond(): void
    {
        $own     = CarbonImmutable::parse('2026-04-06 12:00:00', 'Europe/London');
        $context = new SignInContext(new ClientContext(null, null), notAfter: $own);
        $capped  = $context->withNotAfter($own->utc()->addMilliseconds(500));

        self::assertSame($own->getTimestamp(), $capped->notAfter?->getTimestamp());
        self::assertSame('Europe/London', $capped->notAfter->getTimezone()->getName());
    }

    /**
     * A deadline has passed from the second it names, and a context without one
     * never has.
     *
     * @return void
     */
    public function testTheDeadlineHasPassedFromTheSecondItNames(): void
    {
        $now     = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $context = new SignInContext(new ClientContext(null, null), notAfter: $now);

        self::assertFalse($context->hasPassedDeadline($now->subSecond()));
        self::assertFalse($context->hasPassedDeadline($now->subMillisecond()));
        self::assertTrue($context->hasPassedDeadline($now));
        self::assertTrue($context->hasPassedDeadline($now->addSecond()));
        self::assertFalse((new SignInContext(new ClientContext(null, null)))->hasPassedDeadline($now->addYears(10)));
    }

    /**
     * Built from a request, the context reads the client from it, cleaned as
     * `ClientContext` cleans it, and cleans the description it is given.
     *
     * @return void
     */
    public function testFromRequestReadsTheClient(): void
    {
        $request   = Request::create('/sign-in', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => "Agent\0"]);
        $principal = \Mockery::mock(Principal::class);

        $context = SignInContext::fromRequest($request, "Phone\0", 'iOS', $principal, 'refresh-token');

        self::assertSame('203.0.113.7', $context->client->ip);
        self::assertSame('Agent', $context->client->userAgent);
        self::assertSame('Phone', $context->clientName);
        self::assertSame('iOS', $context->platform);
        self::assertSame($principal, $context->principal);
        self::assertSame('refresh-token', $context->refreshToken?->reveal());

        $bare = SignInContext::fromRequest($request);

        self::assertNull($bare->clientName);
        self::assertNull($bare->refreshToken);
        self::assertNull($context->notAfter);
    }

    /**
     * The refresh token is a sensitive parameter, so a stack trace never shows
     * it.
     *
     * @return void
     */
    public function testTheRefreshTokenIsASensitiveParameter(): void
    {
        foreach ([new \ReflectionMethod(SignInContext::class, '__construct'), new \ReflectionMethod(SignInContext::class, 'fromRequest')] as $method) {

            $parameter = array_values(array_filter($method->getParameters(), static fn (\ReflectionParameter $parameter): bool => $parameter->getName() === 'refreshToken'))[0];

            self::assertNotEmpty($parameter->getAttributes(\SensitiveParameter::class));
        }
    }

    /**
     * The refresh token is held as a secret: one given as a secret is kept as
     * it is, a string is wrapped, and an empty string is no token, so a dump of
     * the context never shows it.
     *
     * @return void
     */
    public function testHoldsTheRefreshTokenAsASecret(): void
    {
        $client = new ClientContext('203.0.113.7', 'agent');
        $secret = new Secret('refresh-token');

        self::assertSame($secret, (new SignInContext($client, refreshToken: $secret))->refreshToken);
        self::assertSame($secret, SignInContext::fromRequest(Request::create('/'), refreshToken: $secret)->refreshToken);
        self::assertNull((new SignInContext($client, refreshToken: ''))->refreshToken);
        self::assertStringNotContainsString('refresh-token', print_r(new SignInContext($client, refreshToken: 'refresh-token'), true));
    }
}
