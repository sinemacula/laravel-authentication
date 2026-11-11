<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithCallers;

/**
 * Query-budget contracts for the caller of a request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerCredentials::class)]
#[CoversClass(Caller::class)]
final class CallerQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithCallers;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createCallerTables();
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
     * Once the guard has authenticated the bearer, its caller, and whether the
     * session the caller holds is its own, cost no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBearersCallerAddsNoQuery(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $stored  = Session::query()->whereKey($session->record->getKey())->firstOrFail();

        $this->bindRequestWithBearer('/caller', $session->tokens->accessToken->reveal());

        Auth::forgetGuards();

        self::assertNotNull(Auth::guard(self::MEMBERS)->user());

        $owns = $this->assertQueryBudget(0, 0, static fn (): bool => (bool) Auth::caller()?->owns($stored));

        self::assertTrue($owns);
    }

    /**
     * A refresh credential is proven once per request, however often the caller
     * is asked for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCredentialIsProvenOncePerRequest(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $request = Request::create('/refresh/sessions/current', 'POST', ['refresh_token' => $session->tokens->refreshToken?->reveal()]);

        DeclaredCredential::refresh(null)->declareOn($request);

        app()->instance('request', $request);

        Auth::forgetGuards();

        $first = $this->assertQueryBudget(3, 0, static fn (): ?Caller => Auth::caller());
        $again = $this->assertQueryBudget(0, 0, static fn (): ?Caller => Auth::caller());

        self::assertSame($session->record->getKey(), $first?->session?->getSessionIdentifier());
        self::assertSame($first, $again);
    }

    /**
     * Admitting another membership of the caller's member by its id reads the
     * member's memberships, once, and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdmittingAnotherPrincipalIsOneRead(): void
    {
        [, [$first, $second]] = $this->seedMember('ada@example.test', 2);

        $session = $this->signedIn('ada@example.test', $first);

        $this->bindRequestWithBearer('/caller', $session->tokens->accessToken->reveal());

        Auth::forgetGuards();

        $caller = Auth::caller();

        self::assertNotNull($caller);
        self::assertTrue($this->assertQueryBudget(1, 0, static fn (): bool => $caller->owns($second)));
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
}
