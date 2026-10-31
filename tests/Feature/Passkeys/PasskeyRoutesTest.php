<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the documented passkey routes, registered as an application
 * would and driven over HTTP with the virtual authenticator as the browser: a
 * signed-in identity registers a passkey, lists and removes it, and signs in
 * with it usernameless; the access token that sign-in returns authenticates
 * through `auth:api`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyService::class)]
#[CoversClass(PasskeySignIn::class)]
final class PasskeyRoutesTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the tables and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware('auth:api')->group(static function (): void {
            Route::post('/passkeys/options', self::registrationOptions(...));
            Route::post('/passkeys', self::register(...));
            Route::get('/passkeys', self::index(...));
            Route::delete('/passkeys/{passkey}', self::remove(...));
            Route::get('/me', static function (): array {
                $identity = Auth::identity();

                return ['email' => $identity instanceof IntegrationIdentity ? $identity->email : null];
            });
        });

        Route::post('/sign-in/passkey/options', static fn (): JsonResponse => response()->json(Auth::passkeys('api')->signInOptions()));
        Route::post('/sign-in/passkey', self::signIn(...));
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
     * A signed-in identity registers a passkey over HTTP, lists it, signs in
     * with it on a new session without naming itself, and that session's access
     * token authenticates; removing the passkey stops it signing in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyIsRegisteredUsedAndRemovedOverHttp(): void
    {
        $this->seedIdentity();

        $access = $this->sessions()->signIn('password', self::credentials())->session?->tokens->accessToken;

        self::assertIsString($access);

        $options = $this->send('/passkeys/options', [], $access)->assertOk()->json();

        self::assertIsArray($options);
        self::assertIsString($options['challenge']);
        self::assertIsArray($options['options']);
        self::assertIsString($options['expires_at']);

        $credential = $this->authenticator()->create($options['options']);
        $registered = $this->send('/passkeys', ['challenge' => $options['challenge'], 'credential' => $credential, 'name' => 'Laptop'], $access)
            ->assertCreated()
            ->assertJsonPath('name', 'Laptop')
            ->json('id');

        self::assertIsString($registered);

        $this->bearer('GET', '/passkeys', $access)->assertOk()->assertJsonCount(1)->assertJsonPath('0.id', $registered);

        $signIn = $this->send('/sign-in/passkey/options', [])->assertOk()->json();

        self::assertIsArray($signIn);

        $assertion = $this->authenticator()->get((array) $signIn['options']);
        $tokens    = $this->send('/sign-in/passkey', ['challenge' => $signIn['challenge'], 'credential' => $assertion])->assertOk()->json();

        self::assertIsArray($tokens);
        self::assertIsString($tokens['access_token']);

        $this->bearer('GET', '/me', $tokens['access_token'])->assertOk()->assertExactJson(['email' => 'ada@example.test']);

        $this->bearer('DELETE', "/passkeys/{$registered}", $access)->assertNoContent();
        $this->bearer('DELETE', "/passkeys/{$registered}", $access)->assertNotFound();

        $again = $this->send('/sign-in/passkey/options', [])->assertOk()->json();

        self::assertIsArray($again);

        $this->send('/sign-in/passkey', ['challenge' => $again['challenge'], 'credential' => $this->authenticator()->get((array) $again['options'])])->assertUnauthorized();
    }

    /**
     * A registration that does not verify is answered 422 with the reason, and
     * the routes behind `auth:api` refuse a request without a token.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRegistrationIsAnswered422(): void
    {
        $this->seedIdentity();

        $access = $this->sessions()->signIn('password', self::credentials())->session?->tokens->accessToken;

        self::assertIsString($access);

        $options = $this->send('/passkeys/options', [], $access)->assertOk()->json();

        self::assertIsArray($options);

        $this->send('/passkeys', ['challenge' => $options['challenge'], 'credential' => '{}'], $access)
            ->assertUnprocessable()
            ->assertExactJson(['error' => PasskeyRegistrationStatus::RESPONSE_INVALID->value]);

        $this->send('/passkeys/options', [])->assertUnauthorized();
    }

    /**
     * Once the client's IP address has used up its options, the sign-in options
     * route answers 429 with the wait.
     *
     * @return void
     */
    public function testAFloodOfSignInOptionsIsAnswered429(): void
    {
        config()->set('authentication.rate_limits.passkey_options.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->send('/sign-in/passkey/options', [])->assertOk();

        $throttled = $this->send('/sign-in/passkey/options', [])->assertTooManyRequests();

        self::assertGreaterThanOrEqual(1, (int) $throttled->headers->get('Retry-After'));
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
     * The registration options route: options for the signed-in identity, shown
     * under its email address.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function registrationOptions(): JsonResponse
    {
        $identity = Auth::identity();

        assert($identity instanceof IntegrationIdentity);

        return response()->json(Auth::passkeys('api')->registrationOptions($identity, $identity->email));
    }

    /**
     * The registration route: register the browser's response for the signed-in
     * identity, 201 with the summary, or 422 with the reason.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function register(Request $request): JsonResponse
    {
        $input = $request->validate([ // @phpstan-ignore staticMethod.dynamicCall
            'challenge'  => ['required', 'string'],
            'credential' => ['required'],
            'name'       => ['nullable', 'string'],
        ]);

        $identity = Auth::identity();

        assert($identity instanceof IntegrationIdentity && (is_array($input['credential']) || is_string($input['credential'])));

        $result = Auth::passkeys('api')->register($identity, $input['challenge'], $input['credential'], $input['name'] ?? null);

        return $result->isRegistered()
            ? response()->json($result->passkey, 201)
            : response()->json(['error' => $result->status->value], 422);
    }

    /**
     * The listing route: the signed-in identity's passkeys.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function index(): JsonResponse
    {
        $identity = Auth::identity();

        assert($identity instanceof IntegrationIdentity);

        return response()->json(Auth::passkeys('api')->passkeys($identity));
    }

    /**
     * The removal route: 204 when the signed-in identity's passkey was removed,
     * 404 otherwise.
     *
     * @param  string  $passkey
     * @return \Illuminate\Http\Response
     *
     * @throws \Throwable
     */
    private static function remove(string $passkey): Response
    {
        $identity = Auth::identity();

        assert($identity instanceof IntegrationIdentity);

        abort_unless(Auth::passkeys('api')->remove($identity, $passkey), 404);

        return response()->noContent();
    }

    /**
     * The passkey sign-in route: sign in through the session service with the
     * challenge and the browser's response, 401 on any failure.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, ?string>
     *
     * @throws \Throwable
     */
    private static function signIn(Request $request): array
    {
        $result = Auth::sessions('api')->signIn('passkey', $request->only(['challenge', 'credential']), SignInContext::fromRequest($request));

        abort_if($result->isFailed(), 401);

        return [
            'access_token'  => $result->session?->tokens->accessToken,
            'refresh_token' => $result->session?->tokens->refreshToken,
        ];
    }

    /**
     * Post the body to the route as a JSON request, with the bearer token when
     * given.
     *
     * @param  string  $path
     * @param  array<string, mixed>  $body
     * @param  ?string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function send(string $path, array $body, #[\SensitiveParameter] ?string $token = null): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson($path, $body, $token === null ? [] : ['Authorization' => 'Bearer ' . $token]);
    }

    /**
     * Send a request with the bearer token.
     *
     * @param  string  $method
     * @param  string  $path
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $method, string $path, #[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->json($method, $path, [], ['Authorization' => 'Bearer ' . $token]);
    }
}
