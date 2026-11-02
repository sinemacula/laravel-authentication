<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Concerns\LooksUpSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of the routes an application registers behind `auth:api` to
 * show one of the signed-in identity's sessions, driven over HTTP:
 * `Auth::sessions('api')->session()` answers the session's summary, marked when
 * it is the one the request is authenticated with, and nothing for a session
 * that is another identity's or no longer active.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversTrait(LooksUpSessions::class)]
final class LooksUpSessionsTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables and register the route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/sessions/{session}', static function (string $session): SessionSummary {

            $identity = Auth::identity();

            assert($identity instanceof Identity);

            return Auth::sessions('api')->session($identity, $session) ?? abort(404);
        });
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
     * The route shows the session the request is authenticated with as the
     * current one, another of the identity's sessions as not current, and one
     * of another guard as well, each with the keys the list gives.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testShowsOneOfTheIdentitysSessionsAndMarksTheCurrentOne(): void
    {
        $this->seedIdentity();

        $phone  = $this->signIn('api', 'Phone');
        $laptop = $this->signIn('api', 'Laptop');
        $admin  = $this->signIn('admin', 'Console');

        $current = $this->show($laptop->tokens->accessToken, self::idOf($laptop))->assertOk();

        self::assertSame(array_keys(SessionSummary::of($laptop->record, true)->toArray()), array_keys((array) $current->json()));

        $current->assertJsonPath('id', self::idOf($laptop))->assertJsonPath('client_name', 'Laptop')->assertJsonPath('current', true);

        $this->show($laptop->tokens->accessToken, self::idOf($phone))->assertOk()->assertJsonPath('client_name', 'Phone')->assertJsonPath('current', false);
        $this->show($laptop->tokens->accessToken, self::idOf($admin))->assertOk()->assertJsonPath('guard', 'admin')->assertJsonPath('current', false);
    }

    /**
     * Another identity's session, a revoked one and a pending one are not
     * found, and the route answers `404` for each alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherIdentitysRevokedOrPendingSessionIsNotFound(): void
    {
        $this->seedIdentity();
        $this->seedIdentity('grace@example.test');

        $current = $this->signIn('api', 'Phone');
        $revoked = $this->signIn('api', 'Revoked');
        $pending = $this->signIn('api', 'Pending');
        $other   = $this->signIn('api', 'Other', 'grace@example.test');

        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);
        Session::query()->whereKey($pending->record->getKey())->update(['status' => 'pending', 'requires' => '["mfa"]']);

        foreach ([$revoked, $pending, $other] as $session) {
            $this->show($current->tokens->accessToken, self::idOf($session))->assertNotFound();
        }
    }

    /**
     * Register the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign the identity in on the guard, from a client of the given name.
     *
     * @param  string  $guard
     * @param  string  $client
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(string $guard, string $client, string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email), SignInContext::fromRequest(app('request'), clientName: $client))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The identifier of the session, as a summary shows it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function idOf(SignedInSession $session): string
    {
        return (string) IdentifierCoercion::stringify($session->record->getSessionIdentifier());
    }

    /**
     * Ask the route for one session, with the access token.
     *
     * @param  string  $token
     * @param  string  $id
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function show(#[\SensitiveParameter] string $token, string $id): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/sessions/' . $id);
    }
}
