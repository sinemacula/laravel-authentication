<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\ChangesIdentifiers;
use Tests\TestCase;

/**
 * Feature tests of the README's identifier change routes, registered as an
 * application would and driven over HTTP with a bearer token from a real
 * sign-in: change the signed-in identity's email address by a code sent to the
 * new one, proven by the session's recent sign-in, or by a link, proven by the
 * current password; with the sender and notifier fakes, on the `sync`
 * connection, so deliveries run once each response is sent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
final class IdentifierChangeRoutesTest extends TestCase
{
    use ChangesIdentifiers;

    /** @var list<array{0: string, 1: string}> The links the link route "mailed", with the address each went to. */
    private static array $mailed = [];

    /**
     * Freeze the clocks, create the table, fake the sender and the notifier,
     * and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->moveTo($this->now);

        self::createChangeableIdentitiesTable();

        self::$mailed   = [];
        $this->sender   = FakeOneTimeCodeSender::fake($this->app);
        $this->notifier = FakeIdentifierChangeNotifier::fake($this->app);

        Route::get('/email/confirm', self::confirmationPage(...))->name('email.confirm');
        Route::post('/email/confirm', self::confirmByLink(...));

        Route::middleware('auth:web')->group(static function (): void {
            Route::post('/email/change', self::requestByCode(...));
            Route::post('/email/change/confirm', self::confirmByCode(...));
            Route::post('/email/change/link', self::requestByLink(...));
            Route::get('/me', static fn (): array => ['email' => Auth::identity()?->getIdentifierForVerification('email')]); // @phpstan-ignore method.notFound
        });
    }

    /**
     * Drop the table and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->stopChanging();

        parent::tearDown();
    }

    /**
     * Signed in moments ago, the identity asks for a code at the new address,
     * which arrives there once the response is sent; the code confirms the
     * change, the old address is told, and the session goes on.
     *
     * @return void
     */
    public function testAnEmailIsChangedByCodeThroughTheRoutes(): void
    {
        self::seedChangeable();

        $access = $this->signIn();

        $this->bearer($access, 'post', '/email/change', ['email' => self::NEW_EMAIL])->assertAccepted()->assertJsonStructure(['expires_at']);

        $code = $this->sender->lastCodeFor(self::NEW_EMAIL);

        self::assertIsString($code);

        $this->bearer($access, 'post', '/email/change/confirm', ['code' => '000000'])->assertUnprocessable();
        $this->bearer($access, 'post', '/email/change/confirm', ['code' => $code])->assertNoContent();

        $notices = array_map(static fn (IdentifierChangeNotice $notice): array => [$notice->previous, $notice->identifier], $this->notifier->sent());

        self::assertSame([[self::EMAIL, self::NEW_EMAIL]], $notices);

        $this->bearer($access, 'get', '/me')->assertOk()->assertExactJson(['email' => self::NEW_EMAIL]);
    }

    /**
     * A session signed in longer ago than the window is asked to
     * reauthenticate, and an address that is not new is refused.
     *
     * @return void
     */
    public function testAStaleSessionMustReauthenticate(): void
    {
        self::seedChangeable();

        $access = $this->signIn();

        $this->bearer($access, 'post', '/email/change', ['email' => ' ADA@example.test'])->assertUnprocessable();

        $this->moveTo($this->now->addSeconds(900));

        $this->bearer($access, 'post', '/email/change', ['email' => self::NEW_EMAIL])->assertForbidden();

        self::assertSame(0, $this->sender->count());
    }

    /**
     * Proven by the current password, the change is confirmed by the link
     * mailed to the new address, which works once and needs no session:
     * following the link only shows the confirmation, so a mail scanner that
     * fetches it changes nothing, and the page's form, posted back to the same
     * signed address, makes the change.
     *
     * @return void
     */
    public function testAnEmailIsChangedByLinkThroughTheRoutes(): void
    {
        self::seedChangeable();

        $access = $this->signIn();

        $this->bearer($access, 'post', '/email/change/link', ['email' => self::NEW_EMAIL, 'password' => 'wrong'])->assertForbidden();
        $this->bearer($access, 'post', '/email/change/link', ['email' => self::NEW_EMAIL, 'password' => self::PASSWORD])->assertAccepted()->assertJsonMissingPath('link');

        self::assertCount(1, self::$mailed);
        self::assertSame(self::NEW_EMAIL, self::$mailed[0][0]);

        $page = (string) $this->get(self::$mailed[0][1])->assertOk()->baseResponse->getContent();

        $this->get(self::$mailed[0][1])->assertOk();
        $this->bearer($access, 'get', '/me')->assertOk()->assertExactJson(['email' => self::EMAIL]);

        self::assertSame(1, preg_match('/<form method="post" action="([^"]+)">/', $page, $form));

        $action = html_entity_decode($form[1]);

        $this->post($action)->assertNoContent();
        $this->post($action)->assertUnprocessable();
        $this->bearer($access, 'get', '/me')->assertOk()->assertExactJson(['email' => self::NEW_EMAIL]);
    }

    /**
     * Register the guards the tests change identifiers through.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }

    /**
     * The README's route that starts a change proven by code: the session's
     * recent sign-in is the proof, and the code goes to the new address.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function requestByCode(Request $request): JsonResponse
    {
        $input    = $request->validate(['email' => ['required', 'string']]); // @phpstan-ignore staticMethod.dynamicCall
        $identity = Auth::identity();
        $device   = Auth::device();

        abort_unless($identity instanceof Identity && $device instanceof Device, 401);

        return self::answer(Auth::identifierChanges('web')->requestByCode($identity, 'email', $input['email'], Reauthentication::device($device)));
    }

    /**
     * The README's route that starts a change proven by link: the current
     * password is the proof, and the link is mailed to the new address, never
     * returned.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function requestByLink(Request $request): JsonResponse
    {
        $input    = $request->validate(['email' => ['required', 'string'], 'password' => ['required', 'string']]); // @phpstan-ignore staticMethod.dynamicCall
        $identity = Auth::identity();

        abort_unless($identity instanceof Identity, 401);

        $result = Auth::identifierChanges('web')->requestByLink($identity, 'email', $input['email'], Reauthentication::password($input['password']), 'email.confirm');

        if ($result->isSent()) {
            self::$mailed[] = [$input['email'], (string) $result->link()];
        }

        return self::answer($result);
    }

    /**
     * The README's route that confirms a change with the code.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     *
     * @throws \Throwable
     */
    private static function confirmByCode(Request $request): Response
    {
        $input    = $request->validate(['code' => ['required', 'string']]); // @phpstan-ignore staticMethod.dynamicCall
        $identity = Auth::identity();

        abort_unless($identity instanceof Identity, 401);

        return self::confirmed(Auth::identifierChanges('web')->confirmByCode($identity, 'email', $input['code']));
    }

    /**
     * The README's route the change link points at: it only shows the
     * confirmation, a form that posts back to the same signed address.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    private static function confirmationPage(Request $request): Response
    {
        return new Response('<form method="post" action="' . e($request->fullUrl()) . '"><button>Confirm the new address</button></form>');
    }

    /**
     * The README's route the confirmation page posts to, which makes the
     * change.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     *
     * @throws \Throwable
     */
    private static function confirmByLink(Request $request): Response
    {
        return self::confirmed(Auth::identifierChanges('web')->confirmByLink($request));
    }

    /**
     * Answer a change request as the README does.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest  $result
     * @return \Illuminate\Http\JsonResponse
     */
    private static function answer(IdentifierChangeRequest $result): JsonResponse
    {
        return match ($result->status) {
            IdentifierChangeRequestStatus::SENT                      => response()->json(['expires_at' => $result->expiresAt?->toIso8601String()], 202),
            IdentifierChangeRequestStatus::RATE_LIMITED              => response()->json(['message' => 'Too Many Attempts.'], 429, ['Retry-After' => (string) $result->retryAfter]),
            IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED => response()->json(['message' => 'Confirm your password first.'], 403),
            IdentifierChangeRequestStatus::IDENTIFIER_INVALID,
            IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED => response()->json(['message' => 'Enter a new email address.'], 422),
        };
    }

    /**
     * Answer a confirmation as the README does.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome  $outcome
     * @return \Illuminate\Http\Response
     */
    private static function confirmed(IdentifierChangeOutcome $outcome): Response
    {
        return match ($outcome) {
            IdentifierChangeOutcome::CHANGED => response()->noContent(),
            IdentifierChangeOutcome::TAKEN   => response('That address is in use.', 409),
            default                          => response('That code or link does not work.', 422),
        };
    }

    /**
     * Sign the seeded identity in with its password and return the access
     * token.
     *
     * @return string
     */
    private function signIn(): string
    {
        $access = $this->sessions('web')->signIn('password', self::credentials(self::EMAIL))->session?->tokens->accessToken;

        self::assertIsString($access);

        return $access;
    }

    /**
     * Send a request with the bearer token.
     *
     * @param  string  $token
     * @param  string  $method
     * @param  string  $path
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token, string $method, string $path, array $body = []): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->json($method, $path, $body);
    }
}
