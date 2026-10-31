<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ConsumerMessages;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Http\ApplicationAuthenticate;
use Tests\TestCase;

/**
 * Feature tests of the messages the package answers a client with, served over
 * HTTP in the application's locale: the `401` of the package guards, whichever
 * `auth` middleware refused the guest, and the `429` of a throttled passkey
 * sign-in or refresh. The application's `lang/fr.json` translates them, and a
 * locale it has no translation for gets the English text; the status and the
 * `Retry-After` header are the same in every locale.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsumerMessages::class)]
#[CoversClass(UnauthenticatedResponse::class)]
#[CoversClass(Authenticate::class)]
#[CoversClass(PasskeyService::class)]
#[CoversClass(JwtGuard::class)]
final class LocalisedMessagesTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the tables, add the routes, and load the application's JSON
     * translations.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/package', static fn (): string => 'ok');
        Route::middleware(ApplicationAuthenticate::class . ':api')->get('/application', static fn (): string => 'ok');
        Route::post('/sign-in/passkey/options', static fn (): mixed => Auth::passkeys('api')->signInOptions());
        Route::post('/refresh', static function (Request $request): array {
            $guard = Auth::manager()->guard('api');

            assert($guard instanceof JwtGuard);

            return ['refreshed' => $guard->refresh($request->string('refresh_token')->value()) !== null];
        });

        app('translator')->addJsonPath(dirname(__DIR__, 2) . '/Fixtures/lang');
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Data provider of a locale, with the `401` message a client is answered
     * with in it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnauthenticatedMessages(): iterable
    {
        yield from [
            'translated'   => ['fr', 'Non authentifié.'],
            'untranslated' => ['de', 'Unauthenticated.'],
            'default'      => ['en', 'Unauthenticated.'],
        ];
    }

    /**
     * A guest refused by the package's `auth` middleware gets `401` with the
     * message in the application's locale, whatever its `Accept` header.
     *
     * @param  string  $locale
     * @param  string  $unauthenticated
     * @return void
     */
    #[DataProvider('provideUnauthenticatedMessages')]
    public function testThePackageMiddlewaresUnauthorizedIsInTheLocale(string $locale, string $unauthenticated): void
    {
        app()->setLocale($locale);

        $this->getJson('/package')->assertUnauthorized()->assertExactJson(['message' => $unauthenticated]);
        $this->get('/package', ['Accept' => 'text/html'])->assertUnauthorized()->assertExactJson(['message' => $unauthenticated]);
    }

    /**
     * A guest on a package guard refused by an application's middleware that
     * extends Laravel's, which raises Laravel's own `Unauthenticated.`, gets
     * the `401` in the application's locale too.
     *
     * @param  string  $locale
     * @param  string  $unauthenticated
     * @return void
     */
    #[DataProvider('provideUnauthenticatedMessages')]
    public function testLaravelsMiddlewaresUnauthorizedIsInTheLocale(string $locale, string $unauthenticated): void
    {
        app()->setLocale($locale);

        $this->getJson('/application')->assertUnauthorized()->assertExactJson(['message' => $unauthenticated]);
    }

    /**
     * Data provider of a locale, with the `429` message a client is answered
     * with in it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideThrottledMessages(): iterable
    {
        yield from [
            'translated'   => ['fr', 'Trop de tentatives.'],
            'untranslated' => ['de', 'Too Many Attempts.'],
            'default'      => ['en', 'Too Many Attempts.'],
        ];
    }

    /**
     * Sign-in options past the client's limit are answered `429` with the wait
     * in `Retry-After` and the message in the application's locale.
     *
     * @param  string  $locale
     * @param  string  $throttled
     * @return void
     */
    #[DataProvider('provideThrottledMessages')]
    public function testThrottledSignInOptionsAreInTheLocale(string $locale, string $throttled): void
    {
        config()->set('authentication.rate_limits.passkey_options.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        app()->setLocale($locale);

        $this->travelTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
        $this->postJson('/sign-in/passkey/options')->assertOk();

        $response = $this->postJson('/sign-in/passkey/options')->assertTooManyRequests()->assertJsonPath('message', $throttled);

        self::assertSame(60, (int) $response->headers->get('Retry-After'));
    }

    /**
     * A refresh the limits refuse is answered `429` with the wait in
     * `Retry-After` and the message in the application's locale.
     *
     * @param  string  $locale
     * @param  string  $throttled
     * @return void
     */
    #[DataProvider('provideThrottledMessages')]
    public function testAThrottledRefreshIsInTheLocale(string $locale, string $throttled): void
    {
        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);
        app()->setLocale($locale);

        $this->refresh()
            ->assertTooManyRequests()
            ->assertHeader('Retry-After', '42')
            ->assertJsonPath('message', $throttled);
    }

    /**
     * The locale is read when the message is rendered, so one application
     * answers each request in the locale it was set to for that request.
     *
     * @return void
     */
    public function testEachRequestIsAnsweredInItsOwnLocale(): void
    {
        app()->setLocale('fr');

        $this->getJson('/package')->assertExactJson(['message' => 'Non authentifié.']);

        app()->setLocale('en');

        $this->getJson('/package')->assertExactJson(['message' => 'Unauthenticated.']);
    }

    /**
     * The translator is resolved as each message is rendered, so one the
     * application binds after the exception handler and its `401` responder
     * were resolved words the messages from then on.
     *
     * @return void
     */
    public function testMessagesAreWordedByTheTranslatorBoundThen(): void
    {
        config()->set('authentication.rate_limits.passkey_options.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->travelTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
        $this->getJson('/package')->assertExactJson(['message' => 'Unauthenticated.']);
        $this->postJson('/sign-in/passkey/options')->assertOk();

        $loader = new ArrayLoader;

        $loader->addMessages('en', '*', ['Unauthenticated.' => 'Please sign in.', 'Too Many Attempts.' => 'Slow down.'], '*');

        app()->instance('translator', new Translator($loader, 'en'));

        $this->getJson('/package')->assertUnauthorized()->assertExactJson(['message' => 'Please sign in.']);
        $this->getJson('/application')->assertUnauthorized()->assertExactJson(['message' => 'Please sign in.']);
        $this->postJson('/sign-in/passkey/options')->assertTooManyRequests()->assertHeader('Retry-After', '60')->assertJsonPath('message', 'Slow down.');
    }

    /**
     * Configure the guards and their relying party.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }

    /**
     * Post a refresh token to the refresh route.
     *
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function refresh(): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson('/refresh', ['refresh_token' => 'not-a-jwt']);
    }
}
