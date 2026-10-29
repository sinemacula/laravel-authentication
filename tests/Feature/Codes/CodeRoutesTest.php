<?php

declare(strict_types = 1);

namespace Tests\Feature\Codes;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;

/**
 * Feature tests of the README's one-time code routes, registered as an
 * application would and driven over HTTP: request a code, sign in with it, and
 * authenticate through `auth:mobile` with the access token; request and confirm
 * a code that verifies the signed-in identity's number; with the code-sender
 * fake, on the `sync` connection and on a faked queue.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(CodeSignIn::class)]
final class CodeRoutesTest extends TestCase
{
    use InteractsWithCodeIdentities;

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender the codes are delivered through. */
    private FakeOneTimeCodeSender $sender;

    /**
     * Freeze the clock, so requests a second apart answer alike, create the
     * table, fake the sender and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        self::createCodeIdentitiesTable();

        $this->sender = FakeOneTimeCodeSender::fake($this->app);

        Route::post('/codes', self::requestCode(...));
        Route::post('/sign-in/code', self::signInWithCode(...));

        Route::middleware('auth:mobile')->group(static function (): void {
            Route::get('/me', static function (): array {
                $identity = Auth::identity();

                return ['phone' => $identity instanceof CodeIdentity ? $identity->phone : null];
            });
            Route::post('/phone/verification', self::requestVerification(...));
            Route::post('/phone/verification/confirm', self::confirmVerification(...));
        });
    }

    /**
     * Release the clock and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The code a request sends arrives once the response is sent, signs in
     * through the route, and the access token authenticates as the holder of
     * the number.
     *
     * @return void
     */
    public function testACodeSignsInThroughTheRoutes(): void
    {
        self::seedCodeIdentity();

        $this->post('/codes', ['phone' => self::PHONE])->assertAccepted()->assertJsonStructure(['expires_at']);

        $code = $this->sender->lastCodeFor(self::PHONE);

        self::assertIsString($code);

        $access = $this->post('/sign-in/code', ['phone' => self::PHONE, 'code' => $code])->assertOk()->json('access_token');

        self::assertIsString($access);

        $this->bearer($access)->assertOk()->assertExactJson(['phone' => self::PHONE]);
        $this->post('/sign-in/code', ['phone' => self::PHONE, 'code' => $code])->assertUnauthorized();
    }

    /**
     * With the queue faked, the request pushes the delivery job; running it
     * delivers the code, which signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeDeliveredByAQueuedJobSignsIn(): void
    {
        self::seedCodeIdentity();

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database']);

        Queue::fake();

        $this->post('/codes', ['phone' => self::PHONE])->assertAccepted();

        self::assertSame(0, $this->sender->count());

        Queue::assertPushed(SendOneTimeCode::class, static function (SendOneTimeCode $job): bool {
            $job->handle(app());

            return true;
        });

        $code = $this->sender->lastCodeFor(self::PHONE);

        self::assertIsString($code);

        $this->post('/sign-in/code', ['phone' => self::PHONE, 'code' => $code])->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
    }

    /**
     * A number no one has is answered exactly as a known one, and nothing is
     * delivered.
     *
     * @return void
     */
    public function testAnUnknownNumberIsAnsweredTheSame(): void
    {
        self::seedCodeIdentity();

        $known   = $this->post('/codes', ['phone' => self::PHONE])->assertAccepted()->json();
        $unknown = $this->post('/codes', ['phone' => self::UNKNOWN_PHONE])->assertAccepted()->json();

        self::assertSame($known, $unknown);
        self::assertNull($this->sender->lastCodeFor(self::UNKNOWN_PHONE));
        self::assertIsString($this->sender->lastCodeFor(self::PHONE));
    }

    /**
     * A second request within the cooldown is answered 429 with the wait, and a
     * number that is not E.164 422; a wrong code 401.
     *
     * @return void
     */
    public function testRefusalsAreAnsweredByTheRoutes(): void
    {
        self::seedCodeIdentity();

        $this->post('/codes', ['phone' => self::PHONE])->assertAccepted();
        $this->post('/codes', ['phone' => self::PHONE])->assertTooManyRequests()->assertHeader('Retry-After', '60');
        $this->post('/codes', ['phone' => '07700 900123'])->assertUnprocessable();

        $wrong = $this->sender->lastCodeFor(self::PHONE) === '000000' ? '111111' : '000000';

        $this->post('/sign-in/code', ['phone' => self::PHONE, 'code' => $wrong])->assertUnauthorized();
    }

    /**
     * A signed-in identity verifies its number with a code sent to it.
     *
     * @return void
     */
    public function testANumberIsVerifiedThroughTheRoutes(): void
    {
        $identity = self::seedCodeIdentity(email: null, verified: false);

        $access = Auth::sessions('mobile')->start($identity, null, 'phone_code')->session?->tokens->accessToken;

        self::assertIsString($access);

        $this->bearer($access, 'post', '/phone/verification')->assertAccepted();

        $code = $this->sender->lastCodeFor(self::PHONE);

        self::assertIsString($code);

        $wrong = $code === '000000' ? '111111' : '000000';

        $this->bearer($access, 'post', '/phone/verification/confirm', ['code' => $wrong])->assertUnprocessable();
        $this->bearer($access, 'post', '/phone/verification/confirm', ['code' => $code])->assertOk()->assertExactJson(['verified' => 'verified']);

        self::assertTrue($identity->fresh()?->hasVerifiedIdentifier('phone'));
    }

    /**
     * Configure the guards.
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

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }

    /**
     * The README's code request route: validate, send, answer a rate-limited
     * request 429 with the wait, an invalid number 422, and every sent code
     * 202, whether or not anyone has the number.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Random\RandomException
     */
    private static function requestCode(Request $request): JsonResponse
    {
        $input  = $request->validate(['phone' => ['required', 'string']]); // @phpstan-ignore staticMethod.dynamicCall
        $result = Auth::codes('mobile')->send('phone_code', ['phone' => $input['phone']]);

        return match ($result->status) {
            CodeRequestStatus::RATE_LIMITED       => response()->json(['message' => 'Too Many Attempts.'], 429, ['Retry-After' => (string) $result->retryAfter]),
            CodeRequestStatus::IDENTIFIER_INVALID => response()->json(['message' => 'Enter a number in international format.'], 422),
            CodeRequestStatus::METHOD_NOT_ALLOWED => abort(403),
            CodeRequestStatus::SENT               => response()->json(['expires_at' => $result->expiresAt?->toIso8601String()], 202),
        };
    }

    /**
     * The README's code sign-in route: validate, sign in through the session
     * service, and hand out the token pair, or answer 401.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, ?string>
     *
     * @throws \Throwable
     */
    private static function signInWithCode(Request $request): array
    {
        $input = $request->validate(['phone' => ['required', 'string'], 'code' => ['required', 'string']]); // @phpstan-ignore staticMethod.dynamicCall

        $result = Auth::sessions('mobile')->signIn('phone_code', ['phone' => $input['phone'], 'code' => $input['code']]);

        abort_unless($result->isSignedIn(), 401);

        return [
            'access_token'  => $result->session?->tokens->accessToken,
            'refresh_token' => $result->session?->tokens->refreshToken,
        ];
    }

    /**
     * The README's route that sends the signed-in identity a code verifying its
     * number.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Random\RandomException
     */
    private static function requestVerification(): JsonResponse
    {
        $identity = Auth::identity();

        abort_unless($identity instanceof Identity, 401);

        $result = Auth::codes('mobile')->sendVerification($identity, 'phone');

        return response()->json(['status' => $result->status->value], $result->isSent() ? 202 : 429);
    }

    /**
     * The README's route that checks the code and verifies the signed-in
     * identity's number.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, string>
     */
    private static function confirmVerification(Request $request): array
    {
        $input    = $request->validate(['code' => ['required', 'string']]); // @phpstan-ignore staticMethod.dynamicCall
        $identity = Auth::identity();

        abort_unless($identity instanceof Identity, 401);

        $result = Auth::codes('mobile')->verify($identity, 'phone', $input['code']);

        abort_unless($result instanceof IdentifierVerification, 422);

        return ['verified' => $result->value];
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
    private function bearer(#[\SensitiveParameter] string $token, string $method = 'get', string $path = '/me', array $body = []): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->json($method, $path, $body);
    }
}
