<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Events\Verified;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\URL;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for verifying identifiers by signed link, through a route of
 * the application's that consumes the link: every outcome, and the
 * `AuthenticationFailed` each refusal reports.
 *
 * Every package event and Laravel's auth events are recorded, so asserting the
 * one event an outcome dispatches also proves it signed nobody in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationLinks::class)]
final class VerificationLinksTest extends TestCase
{
    use InteractsWithVerifiableIdentities;

    /** @var string Guard the links verify for. */
    private const string GUARD = 'api';

    /** @var string Name of the application's verification route. */
    private const string ROUTE = 'verification.verify';

    /** @var list<object> Every authentication event dispatched, in order. */
    private array $events = [];

    /**
     * Create the identities table and the route that consumes links.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2027-03-01 08:30:00'));

        self::createVerifiableIdentitiesTable();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Route::get('/verify/{channel}', fn (Request $request): array => [
            'outcome' => $this->links()->consume($request)->value,
            'user'    => Auth::guard(self::GUARD)->hasUser(),
        ])->name(self::ROUTE);

        $events = [AuthenticationEvent::class, Attempting::class, Validated::class, Login::class, Authenticated::class, Failed::class, Logout::class, Verified::class];

        Event::listen($events, function (object $event): void {
            $this->events[] = $event;
        });
    }

    /**
     * Drop the identities table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');
        Schema::dropIfExists('verifiable_identities');
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A link carries the route's own parameters, the guard, the identity, the
     * type, its purpose and a digest of the normalised identifier, never the
     * identifier itself, and expires after the configured hour.
     *
     * @return void
     */
    public function testLinkIsBoundToItsPurposeGuardIdentityAndIdentifier(): void
    {
        $identity = self::seedVerifiableIdentity();

        $query = $this->queryOf($this->link($identity, ['channel' => 'mail']));

        self::assertStringStartsWith('http://localhost/verify/mail?', $this->link($identity, ['channel' => 'mail']));
        self::assertSame(self::GUARD, $query['guard']);
        self::assertSame((string) $identity->id, $query['identity']);
        self::assertSame('email', $query['type']);
        self::assertSame('verify_identifier', $query['purpose']);
        self::assertSame(hash('sha256', 'ben@example.com'), $query['hash']);
        self::assertSame((string) Carbon::now()->addHour()->getTimestamp(), $query['expires']);
        self::assertArrayHasKey('signature', $query);
        self::assertStringNotContainsString('example.com', $this->link($identity, ['channel' => 'mail']));
    }

    /**
     * Following the link verifies the identifier once, signs nobody in, and
     * following it again reports the identifier already verified.
     *
     * @return void
     */
    public function testFollowingTheLinkVerifiesTheIdentifierOnce(): void
    {
        $identity = self::seedVerifiableIdentity();
        $link     = $this->link($identity, ['channel' => 'mail']);

        $this->withHeader('User-Agent', 'Mail/1.0')->getJson($link)->assertOk()->assertExactJson(['outcome' => 'verified', 'user' => false]);
        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'already_verified', 'user' => false]);

        self::assertNotNull(DB::table('verifiable_identities')->value('email_verified_at'));
        self::assertSame(0, DB::table('devices')->count());
        self::assertCount(1, $this->events);
        self::assertInstanceOf(IdentifierVerified::class, $this->events[0]);
        self::assertSame(['Mail/1.0', self::GUARD, 'email'], [$this->events[0]->context->client->userAgent, $this->events[0]->context->guard, $this->events[0]->type]);
    }

    /**
     * Ways an authentic link stops proving its identity's current identifier.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\VerifiableIdentity): mixed, 1: bool}>
     */
    public static function provideLinksThatNoLongerProveTheIdentifier(): iterable
    {
        yield from [
            'a changed identifier'         => [static fn (VerifiableIdentity $identity): bool => $identity->update(['email' => 'New@Example.com']), true],
            'a removed identifier'         => [static fn (VerifiableIdentity $identity): bool => $identity->update(['email' => null]), true],
            'an identifier now unreadable' => [static fn (VerifiableIdentity $identity): int => DB::table('verifiable_identities')->update(['email' => '   ']), true],
            'a deleted identity'           => [static fn (VerifiableIdentity $identity): ?bool => $identity->delete(), false],
        ];
    }

    /**
     * An authentic link whose identifier has since changed, been removed or
     * become one its normaliser rejects, or whose identity is gone, is
     * `invalid`, as a tampered link is, so the answer says nothing about the
     * account. The event names the guard the link was signed for, and the
     * identity once it was loaded.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\VerifiableIdentity): mixed  $change
     * @param  bool  $loaded
     * @return void
     */
    #[DataProvider('provideLinksThatNoLongerProveTheIdentifier')]
    public function testLinkThatNoLongerProvesTheIdentifierIsInvalid(\Closure $change, bool $loaded): void
    {
        $identity = self::seedVerifiableIdentity();
        $link     = $this->link($identity, ['channel' => 'mail']);

        $change($identity);

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'invalid', 'user' => false]);

        $failed = $this->failure(FailureReason::INVALID_CREDENTIALS);

        self::assertSame(self::GUARD, $failed->context->guard);
        self::assertSame($loaded ? (string) $identity->id : null, $failed->context->identityId);
        self::assertSame(0, DB::table('verifiable_identities')->whereNotNull('email_verified_at')->count());
    }

    /**
     * A link past its lifetime is `expired`, reported as `link_expired` for the
     * guard it was signed for; one with a lifetime of its own lasts that long.
     *
     * @return void
     */
    public function testLinkExpires(): void
    {
        $identity = self::seedVerifiableIdentity();
        $hour     = $this->link($identity, ['channel' => 'mail']);
        $day      = $this->links()->create(self::GUARD, $identity, 'email', self::ROUTE, ['channel' => 'mail'], 1440);

        Carbon::setTestNow(Carbon::now()->addHour()->addSecond());

        $this->withHeader('User-Agent', 'Mail/1.0')->getJson($hour)->assertOk()->assertExactJson(['outcome' => 'expired', 'user' => false]);

        $failed = $this->failure(FailureReason::LINK_EXPIRED);

        self::assertSame([self::GUARD, null, 'Mail/1.0'], [$failed->context->guard, $failed->context->identity, $failed->context->client->userAgent]);

        $this->events = [];

        $this->getJson($day)->assertOk()->assertExactJson(['outcome' => 'verified', 'user' => false]);
    }

    /**
     * Its signature is checked before its expiry, and both before any identity
     * is read: an expired link that was tampered with is `invalid`, naming no
     * guard, and an authentic expired one is `expired` without a query, even
     * once its identity is gone or for a guard no longer configured.
     *
     * @return void
     */
    public function testSignatureIsCheckedBeforeExpiryAndBothBeforeTheIdentity(): void
    {
        $identity = self::seedVerifiableIdentity();
        $link     = $this->link($identity, ['channel' => 'mail']);

        Carbon::setTestNow(Carbon::now()->addDay());

        $this->getJson(str_replace('identity=', 'identity=9', $link))->assertOk()->assertExactJson(['outcome' => 'invalid', 'user' => false]);

        self::assertNull($this->failure(FailureReason::INVALID_CREDENTIALS)->context->guard);

        $identity->delete();
        $this->events = [];

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'expired', 'user' => false]);

        self::assertSame(0, $queries);
        self::assertSame(self::GUARD, $this->failure(FailureReason::LINK_EXPIRED)->context->guard);

        config()->set('auth.guards.' . self::GUARD, null);
        $this->events = [];

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'expired', 'user' => false]);

        self::assertNull($this->failure(FailureReason::LINK_EXPIRED)->context->guard);
    }

    /**
     * When the identifier changes while the link is being verified, the
     * verifier records nothing and answers `mismatch`, which the link answers
     * as it is: the link was accepted, so no failure is reported, and nothing
     * is verified.
     *
     * @return void
     */
    public function testTheVerifiersMismatchIsAnsweredAsItIs(): void
    {
        $identity = self::seedVerifiableIdentity();
        $link     = $this->link($identity, ['channel' => 'mail']);

        Event::listen('eloquent.retrieved: ' . VerifiableIdentity::class, static function (): void {
            DB::table('verifiable_identities')->update(['email' => 'eve@example.com']);
        });

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'mismatch', 'user' => false]);

        self::assertSame([], $this->events);
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));
    }

    /**
     * A link signed by hand, as the malformed expiries below are, verifies when
     * its expiry is well formed, so each of them is refused for its expiry
     * alone.
     *
     * @return void
     */
    public function testAHandSignedLinkWithAWellFormedExpiryVerifies(): void
    {
        $identity = self::seedVerifiableIdentity();

        $link = self::handSigned([
            'guard'    => self::GUARD,
            'identity' => $identity->getKey(),
            'type'     => 'email',
            'purpose'  => VerificationLinks::PURPOSE,
            'hash'     => hash('sha256', 'ben@example.com'),
        ], Carbon::now()->addHour()->getTimestamp());

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'verified', 'user' => false]);
    }

    /**
     * Links that were tampered with, signed for another purpose or without a
     * well-formed expiry, or that name no usable guard, type or identity, with
     * the guard their refusal names, none until the link is known authentic and
     * its guard a configured JWT guard, and whether it names the identity.
     *
     * @return iterable<string, array{0: \Closure(string, \Tests\Integration\Fixtures\VerifiableIdentity): string, 1: ?string, 2: bool}>
     */
    public static function provideInvalidLinks(): iterable
    {
        $signed = static fn (array $parameters): string => URL::temporarySignedRoute(self::ROUTE, Carbon::now()->addHour(), ['channel' => 'mail', ...$parameters]);

        $valid = static fn (VerifiableIdentity $identity): array => [
            'guard'    => self::GUARD,
            'identity' => $identity->getKey(),
            'type'     => 'email',
            'purpose'  => 'verify_identifier',
            'hash'     => hash('sha256', 'ben@example.com'),
        ];

        $with = static fn (array $changes): \Closure => static fn (string $link, VerifiableIdentity $identity): string => $signed($changes + $valid($identity));

        $without = static fn (string $key): \Closure => static fn (string $link, VerifiableIdentity $identity): string => $signed(
            array_diff_key($valid($identity), [$key => true]),
        );

        $unexpiring = static fn (string $link, VerifiableIdentity $identity): string => URL::signedRoute(self::ROUTE, ['channel' => 'mail', ...$valid($identity)]);

        $expiring = static fn (mixed $expires): \Closure => static fn (string $link, VerifiableIdentity $identity): string => self::handSigned($valid($identity), $expires);

        $padded = static fn (string $link, VerifiableIdentity $identity): string => self::handSigned($valid($identity), '0' . Carbon::now()->addHour()->getTimestamp());

        yield from [
            'a changed identity'           => [static fn (string $link): string => str_replace('identity=', 'identity=9', $link), null, false],
            'a changed signature'          => [static fn (string $link): string => substr($link, 0, -1) . (str_ends_with($link, 'a') ? 'b' : 'a'), null, false],
            'no signature'                 => [static fn (string $link): string => (string) preg_replace('/&signature=[^&]+/', '', $link), null, false],
            'another purpose'              => [$with(['purpose' => 'reset_password']), null, false],
            'no purpose'                   => [$without('purpose'), null, false],
            'no expiry'                    => [$unexpiring, null, false],
            'an expiry that is no time'    => [$expiring('soon'), null, false],
            'an empty expiry'              => [$expiring(''), null, false],
            'an array expiry'              => [$expiring([Carbon::now()->addHour()->getTimestamp()]), null, false],
            'a zero expiry'                => [$expiring('0'), null, false],
            'a padded expiry'              => [$padded, null, false],
            'a session guard'              => [$with(['guard' => 'web']), null, false],
            'an unknown guard'             => [$with(['guard' => 'nope']), null, false],
            'a guard with no provider'     => [$with(['guard' => 'providerless']), null, false],
            'an array guard'               => [$with(['guard' => [self::GUARD]]), null, false],
            'a malformed type'             => [$with(['type' => 'Email']), null, false],
            'an array type'                => [$with(['type' => ['email']]), null, false],
            'no hash'                      => [$without('hash'), null, false],
            'an array hash'                => [$with(['hash' => [hash('sha256', 'ben@example.com')]]), null, false],
            'an array identity'            => [$with(['identity' => ['1']]), null, false],
            'another hash'                 => [$with(['hash' => hash('sha256', 'eve@example.com')]), self::GUARD, true],
            'an unknown identity'          => [$with(['identity' => '999']), self::GUARD, false],
            'an identity of another guard' => [$with(['guard' => 'plain']), 'plain', false],
        ];
    }

    /**
     * An invalid link verifies nothing, signs nobody in, and is reported as
     * `invalid_credentials` on the `identifier_verification` flow, naming no
     * identity it did not load. The other guard's identity model has a row
     * under the same key, which cannot verify identifiers.
     *
     * @param  \Closure(string, \Tests\Integration\Fixtures\VerifiableIdentity): string  $tamper
     * @param  ?string  $guard
     * @param  bool  $loaded
     * @return void
     */
    #[DataProvider('provideInvalidLinks')]
    public function testInvalidLinkVerifiesNothing(\Closure $tamper, ?string $guard, bool $loaded): void
    {
        $identity = self::seedVerifiableIdentity();

        StubPrincipal::query()->create(['id' => $identity->getKey(), 'email' => 'ben@example.com', 'password' => 'unused']);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
            ->getJson($tamper($this->link($identity, ['channel' => 'mail']), $identity))
            ->assertOk()
            ->assertExactJson(['outcome' => 'invalid', 'user' => false]);

        $failed = $this->failure(FailureReason::INVALID_CREDENTIALS);

        self::assertSame($guard, $failed->context->guard);
        self::assertSame('203.0.113.9', $failed->context->client->ip);
        self::assertSame($loaded ? (string) $identity->id : null, $failed->context->identityId);
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));
    }

    /**
     * A link cannot be created with a reserved parameter name, for an identity
     * without the identifier, for a guard that is not a JWT guard, or for an
     * identity that cannot verify identifiers.
     *
     * @return void
     */
    public function testRefusesLinksThatCouldNotBeTrusted(): void
    {
        $identity = self::seedVerifiableIdentity();

        $create = fn (string $guard, Identity $identity, array $parameters = ['channel' => 'mail'], string $type = 'email'): \Closure => fn (): string => $this->links()->create(
            $guard,
            $identity,
            $type,
            self::ROUTE,
            $parameters,
        );

        $blank = self::seedVerifiableIdentity(null);

        $blank->setRawAttributes(['email' => '   '] + $blank->getAttributes());

        $reserved = ['channel' => 'mail', 'purpose' => 'x', 'hash' => 'y'];
        $missing  = ' identifier that can be verified.';

        $this->assertRefused(\InvalidArgumentException::class, 'may not use the reserved names: purpose, hash.', $create(self::GUARD, $identity, $reserved));
        $this->assertRefused(\InvalidArgumentException::class, VerifiableIdentity::class . ' has no phone' . $missing, $create(self::GUARD, $identity, type: 'phone'));
        $this->assertRefused(\InvalidArgumentException::class, VerifiableIdentity::class . ' has no email' . $missing, $create(self::GUARD, $blank));
        $this->assertRefused(\InvalidArgumentException::class, 'Auth guard [web] is not a configured jwt guard.', $create('web', $identity));
        $this->assertRefused(\InvalidArgumentException::class, 'Auth guard [nope] is not a configured jwt guard.', $create('nope', $identity));
        $this->assertRefused(\InvalidArgumentException::class, 'Identifier type [Email] must be', $create(self::GUARD, $identity, type: 'Email'));
        $this->assertRefused(\LogicException::class, 'cannot verify identifiers', $create(self::GUARD, new PlainIdentityFixture(1)));
    }

    /**
     * A route that takes reserved names as placeholders would carry the link's
     * fields in its path, where `consume()` never reads them, so every link to
     * it would be refused: creating one fails instead, naming the placeholders.
     *
     * @return void
     */
    public function testRefusesARouteThatTakesReservedNamesAsPlaceholders(): void
    {
        Route::get('/verify/{type}/{hash}', fn (Request $request): array => ['outcome' => $this->links()->consume($request)->value])->name('verification.placeholders');

        $identity = self::seedVerifiableIdentity();

        $this->assertRefused(
            \InvalidArgumentException::class,
            'Verification route [verification.placeholders] may not use the reserved names as placeholders: type, hash.',
            fn (): string => $this->links()->create(self::GUARD, $identity, 'email', 'verification.placeholders'),
        );

        $signed = URL::temporarySignedRoute('verification.placeholders', Carbon::now()->addHour(), [
            'guard'    => self::GUARD,
            'identity' => $identity->id,
            'type'     => 'email',
            'purpose'  => VerificationLinks::PURPOSE,
            'hash'     => hash('sha256', 'ben@example.com'),
        ]);

        $this->getJson($signed)->assertOk()->assertExactJson(['outcome' => 'invalid']);
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));
    }

    /**
     * Link lifetimes, as configured or given, that are refused.
     *
     * @return iterable<string, array{0: mixed, 1: ?int}>
     */
    public static function provideInvalidLifetimes(): iterable
    {
        yield from [
            'configured zero'        => [0, null],
            'configured over a week' => [10081, null],
            'configured padded'      => ['060', null],
            'configured text'        => ['an hour', null],
            'configured null'        => [null, null],
            'given zero'             => [60, 0],
            'given over a week'      => [60, 10081],
        ];
    }

    /**
     * A lifetime outside a minute to a week fails closed.
     *
     * @param  mixed  $configured
     * @param  ?int  $given
     * @return void
     */
    #[DataProvider('provideInvalidLifetimes')]
    public function testInvalidLifetimeFailsClosed(mixed $configured, ?int $given): void
    {
        config()->set('authentication.verification.link_ttl_minutes', $configured);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The verification link lifetime, `authentication.verification.link_ttl_minutes` or the one given,'
            . ' must be an integer from 1 to 10080 minutes.',
        );

        $this->links()->create(self::GUARD, self::seedVerifiableIdentity(), 'email', self::ROUTE, ['channel' => 'mail'], $given);
    }

    /**
     * A lifetime of a minute or a week, configured as `env()` returns it, is
     * accepted.
     *
     * @return void
     */
    public function testLifetimeBoundsAreAccepted(): void
    {
        $identity = self::seedVerifiableIdentity();

        config()->set('authentication.verification.link_ttl_minutes', '10080');

        self::assertStringContainsString('expires=' . Carbon::now()->addWeek()->getTimestamp(), $this->link($identity, ['channel' => 'mail']));
        $minute = $this->links()->create(self::GUARD, $identity, 'email', self::ROUTE, ['channel' => 'mail'], 1);

        self::assertStringContainsString('expires=' . Carbon::now()->addMinute()->getTimestamp(), $minute);
    }

    /**
     * Configure a JWT guard over the identities, a session guard, a JWT guard
     * over another identity model, and one with no identity provider.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'verifiable']);
        $config->set('auth.guards.plain', ['driver' => 'jwt', 'provider' => 'plain']);
        $config->set('auth.guards.providerless', ['driver' => 'jwt']);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'verifiable']);
        $config->set('auth.providers.verifiable', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
        $config->set('auth.providers.plain', ['driver' => 'model', 'model' => StubPrincipal::class]);
    }

    /**
     * The one event dispatched, a failure on the `identifier_verification` flow
     * for the reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function failure(FailureReason $reason): AuthenticationFailed
    {
        self::assertCount(1, $this->events);

        $failed = $this->events[0];

        self::assertInstanceOf(AuthenticationFailed::class, $failed);
        self::assertSame([AuthenticationFlow::IDENTIFIER_VERIFICATION, $reason, null, null], [$failed->flow, $failed->reason, $failed->identifier, $failed->retryAfter]);

        return $failed;
    }

    /**
     * The links helper.
     *
     * @return \SineMacula\Laravel\Authentication\Verification\VerificationLinks
     */
    private function links(): VerificationLinks
    {
        $links = $this->app?->make(VerificationLinks::class);

        self::assertInstanceOf(VerificationLinks::class, $links);

        return $links;
    }

    /**
     * A link for the identity's identifier of the type, with the default
     * lifetime.
     *
     * @param  \Tests\Integration\Fixtures\VerifiableIdentity  $identity
     * @param  array<string, mixed>  $parameters
     * @param  string  $type
     * @return string
     */
    private function link(VerifiableIdentity $identity, array $parameters, string $type = 'email'): string
    {
        return $this->links()->create(self::GUARD, $identity, $type, self::ROUTE, $parameters);
    }

    /**
     * A link to the route with the fields and the expiry as given, signed with
     * the application key as Laravel signs one, so an expiry its URL generator
     * would refuse to sign can be tried.
     *
     * @param  array<string, mixed>  $fields
     * @param  mixed  $expires
     * @return string
     */
    private static function handSigned(array $fields, mixed $expires): string
    {
        $url = URL::route(self::ROUTE, ['channel' => 'mail', ...$fields, 'expires' => $expires]);

        return $url . '&signature=' . hash_hmac('sha256', $url, config()->string('app.key'));
    }

    /**
     * The query parameters of a link.
     *
     * @param  string  $link
     * @return array<array-key, mixed>
     */
    private function queryOf(string $link): array
    {
        $query = parse_url($link, PHP_URL_QUERY);

        self::assertIsString($query);

        parse_str($query, $parameters);

        return $parameters;
    }

    /**
     * Assert the callback throws the exception class with a message that
     * contains the given text.
     *
     * @param  class-string<\Throwable>  $class
     * @param  string  $message
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function assertRefused(string $class, string $message, \Closure $callback): void
    {
        try {
            $callback();
        } catch (\Throwable $e) {
            self::assertInstanceOf($class, $e);
            self::assertStringContainsString($message, $e->getMessage());

            return;
        }

        self::fail("Expected {$class}: {$message}");
    }
}
