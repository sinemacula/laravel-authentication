<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
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
use SineMacula\Laravel\Authentication\Contracts\Identity;
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
 * the application's that consumes the link.
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
            'outcome' => $this->links()->consume($request)?->value,
            'user'    => Auth::guard(self::GUARD)->hasUser(),
        ])->name(self::ROUTE);
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
        Event::fake([IdentifierVerified::class]);

        $identity = self::seedVerifiableIdentity();
        $link     = $this->link($identity, ['channel' => 'mail']);

        $this->withHeader('User-Agent', 'Mail/1.0')->getJson($link)->assertOk()->assertExactJson(['outcome' => 'verified', 'user' => false]);
        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'already_verified', 'user' => false]);

        self::assertNotNull(DB::table('verifiable_identities')->value('email_verified_at'));
        self::assertSame(0, DB::table('devices')->count());

        Event::assertDispatchedTimes(IdentifierVerified::class, 1);
        Event::assertDispatched(
            IdentifierVerified::class,
            static fn (IdentifierVerified $event): bool => $event->client?->userAgent === 'Mail/1.0' && $event->guard === self::GUARD,
        );
    }

    /**
     * A link whose identifier has since changed or been removed, or whose
     * identity is gone, verifies nothing.
     *
     * @return void
     */
    public function testLinkForAnIdentifierThatChangedVerifiesNothing(): void
    {
        $identity = self::seedVerifiableIdentity();
        $link     = $this->link($identity, ['channel' => 'mail']);

        $identity->update(['email' => 'New@Example.com']);

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => null, 'user' => false]);

        $identity->update(['email' => null]);

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => null, 'user' => false]);

        $identity->delete();

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => null, 'user' => false]);
        self::assertSame(0, DB::table('verifiable_identities')->whereNotNull('email_verified_at')->count());
    }

    /**
     * A link past its lifetime verifies nothing; one with a lifetime of its own
     * lasts that long.
     *
     * @return void
     */
    public function testLinkExpires(): void
    {
        $identity = self::seedVerifiableIdentity();
        $hour     = $this->link($identity, ['channel' => 'mail']);
        $day      = $this->links()->create(self::GUARD, $identity, 'email', self::ROUTE, ['channel' => 'mail'], 1440);

        Carbon::setTestNow(Carbon::now()->addHour()->addSecond());

        $this->getJson($hour)->assertOk()->assertExactJson(['outcome' => null, 'user' => false]);
        $this->getJson($day)->assertOk()->assertExactJson(['outcome' => 'verified', 'user' => false]);
    }

    /**
     * Links that were tampered with, signed for another purpose, or that name
     * no usable guard, type or identity.
     *
     * @return iterable<string, array{0: \Closure(string, \Tests\Integration\Fixtures\VerifiableIdentity): string}>
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

        yield from [
            'a changed identity'           => [static fn (string $link): string => str_replace('identity=', 'identity=9', $link)],
            'a changed signature'          => [static fn (string $link): string => substr($link, 0, -1) . (str_ends_with($link, 'a') ? 'b' : 'a')],
            'no signature'                 => [static fn (string $link): string => (string) preg_replace('/&signature=[^&]+/', '', $link)],
            'another purpose'              => [$with(['purpose' => 'reset_password'])],
            'no purpose'                   => [$without('purpose')],
            'a session guard'              => [$with(['guard' => 'web'])],
            'an unknown guard'             => [$with(['guard' => 'nope'])],
            'a malformed type'             => [$with(['type' => 'Email'])],
            'an array type'                => [$with(['type' => ['email']])],
            'no hash'                      => [$without('hash')],
            'another hash'                 => [$with(['hash' => hash('sha256', 'eve@example.com')])],
            'an array identity'            => [static fn (string $link, VerifiableIdentity $identity): string => $signed(['identity' => [$identity->id]] + $valid($identity))],
            'an identity of another guard' => [$with(['guard' => 'plain'])],
        ];
    }

    /**
     * An invalid link verifies nothing and signs nobody in. The other guard's
     * identity model has a row under the same key, which cannot verify
     * identifiers.
     *
     * @param  \Closure(string, \Tests\Integration\Fixtures\VerifiableIdentity): string  $tamper
     * @return void
     */
    #[DataProvider('provideInvalidLinks')]
    public function testInvalidLinkVerifiesNothing(\Closure $tamper): void
    {
        $identity = self::seedVerifiableIdentity();

        StubPrincipal::query()->create(['id' => $identity->getKey(), 'email' => 'ben@example.com', 'password' => 'unused']);

        $this->getJson($tamper($this->link($identity, ['channel' => 'mail']), $identity))
            ->assertOk()
            ->assertExactJson(['outcome' => null, 'user' => false]);

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
     * Configure a JWT guard over the identities, a session guard, and a JWT
     * guard over another identity model.
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
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'verifiable']);
        $config->set('auth.providers.verifiable', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
        $config->set('auth.providers.plain', ['driver' => 'model', 'model' => StubPrincipal::class]);
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
