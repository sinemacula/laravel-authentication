<?php

declare(strict_types = 1);

namespace Tests\Feature\Callers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithCallers;
use Tests\TestCase;

/**
 * Feature tests of an application's session route binding built on the
 * request's caller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Caller::class)]
final class CallerRouteBindingTest extends TestCase
{
    use InteractsWithCallers;

    /**
     * Create the tables, and register the application's binding and routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createCallerTables();

        Route::bind('session', static function (string $value): Session {
            $caller = Auth::caller() ?? throw new AuthenticationException;

            if ($value === 'current') {
                return $caller->session instanceof Session ? $caller->session : abort(404);
            }

            $session = WriteConnection::query(Session::query())->find($value);

            return $session instanceof Session && $caller->owns($session) ? $session : abort(404);
        });

        Route::middleware(['auth:' . self::MEMBERS, SubstituteBindings::class])
            ->get('/sessions/{session}', static fn (Session $session): array => ['id' => $session->getKey()]);

        Route::middleware(['authentication.refresh:' . self::MEMBERS, SubstituteBindings::class])
            ->post('/auth/sessions/{session}', static fn (Session $session): array => ['id' => $session->getKey()]);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropCallerTables();

        parent::tearDown();
    }

    /**
     * Behind a bearer, `current` is the bearer's session and an id binds any
     * session the caller's member owns, never another member's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerBindsItsOwnSessions(): void
    {
        $this->seedMember('ada@example.test');
        $this->seedMember('grace@example.test');

        $current = $this->signedIn('ada@example.test');
        $another = $this->signedIn('ada@example.test');
        $graces  = $this->signedIn('grace@example.test');
        $token   = $current->tokens->accessToken->reveal();

        $this->bearer('/sessions/current', $token)->assertOk()->assertExactJson(['id' => $current->record->getKey()]);
        $this->bearer('/sessions/' . self::id($another->record->getKey()), $token)->assertOk()->assertExactJson(['id' => $another->record->getKey()]);
        $this->bearer('/sessions/' . self::id($graces->record->getKey()), $token)->assertNotFound();
    }

    /**
     * Behind the refresh credential, only the session the token proves is
     * bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCredentialBindsOnlyTheSessionItProves(): void
    {
        $this->seedMember('ada@example.test');

        $proven  = $this->signedIn('ada@example.test');
        $another = $this->signedIn('ada@example.test');
        $body    = ['refresh_token' => $proven->tokens->refreshToken?->reveal()];

        Auth::forgetGuards();

        $this->postJson('/auth/sessions/current', $body)->assertOk()->assertExactJson(['id' => $proven->record->getKey()]);
        $this->postJson('/auth/sessions/' . self::id($proven->record->getKey()), $body)->assertOk();
        $this->postJson('/auth/sessions/' . self::id($another->record->getKey()), $body)->assertNotFound();
        $this->post('/auth/sessions/current')->assertUnauthorized()->assertExactJson(['message' => 'Unauthenticated.']);
    }

    /**
     * Register the members' guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureCallerGuards($app->make(ConfigRepository::class));
    }

    /**
     * Get the route with the access token, on guards resolved afresh.
     *
     * @param  string  $uri
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $uri, #[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->getJson($uri, ['Authorization' => 'Bearer ' . $token]);
    }

    /**
     * The session key as it appears in a URL.
     *
     * @param  mixed  $key
     * @return string
     */
    private static function id(mixed $key): string
    {
        return (string) IdentifierCoercion::stringify($key);
    }
}
