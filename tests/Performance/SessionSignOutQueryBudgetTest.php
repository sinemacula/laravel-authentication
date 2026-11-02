<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;
use SineMacula\Laravel\Authentication\Sessions\RefreshProof;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget contracts for the paths that prove a session by its refresh
 * token without rotating it: a sign-out by refresh token reads the session and
 * its owner and writes the one conditional revocation; reading the refresh
 * credential reads the same two rows and writes nothing, and reading the caller
 * from a member's refresh credential with an active tenant adds no query for
 * the tenant's policy; and a refusal the transport makes, or a token that does
 * not parse, costs no query at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionSignOut::class)]
#[CoversClass(RefreshProof::class)]
#[CoversClass(SessionRefresh::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(CallerCredentials::class)]
#[CoversTrait(EndsSessions::class)]
#[CoversTrait(RefreshesSessions::class)]
final class SessionSignOutQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
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
     * Signing out by refresh token reads the session and its owner, and writes
     * the one conditional revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignOutByRefreshTokenIsTwoReadsAndOneUpdate(): void
    {
        $this->seedIdentity();

        $sessions = $this->serving(['refresh_token' => $this->signedIn()]);

        self::assertTrue($this->assertQueryBudget(2, 1, static fn (): bool => $sessions->signOutFromRequest()->isSignedOut()));
    }

    /**
     * A sign-out whose refresh token does not parse, or that the transport
     * refuses, costs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSignOutBeforeTheSessionCostsNoQuery(): void
    {
        $invalid = $this->serving(['refresh_token' => 'not-a-token']);

        self::assertSame(FailureReason::TOKEN_INVALID, $this->assertQueryBudget(0, 0, static fn (): ?FailureReason => $invalid->signOutFromRequest()->reason));

        $conflict = $this->serving(['refresh_token' => 'one-token'], ['HTTP_X_REFRESH_TOKEN' => 'another-token']);

        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $this->assertQueryBudget(0, 0, static fn (): ?FailureReason => $conflict->signOutFromRequest()->reason));
    }

    /**
     * Reading the refresh credential reads the session and its owner, and
     * writes nothing: the session keeps its rotation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadingTheRefreshCredentialIsTwoReadsAndNoWrite(): void
    {
        $this->seedIdentity();

        $sessions = $this->serving(['refresh_token' => $this->signedIn()]);

        self::assertInstanceOf(RefreshCredential::class, $this->assertQueryBudget(2, 0, static fn (): mixed => $sessions->refreshCredentialFromRequest()));
    }

    /**
     * Reading the caller from a member's refresh credential, on a session with
     * an active tenant, reads the session, the member, its membership and the
     * tenant, and writes nothing: the default tenant policy adds no query.
     * Asked again, the request's caller costs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadingAMembersRefreshCredentialsCallerIsFourReadsAndNoWrite(): void
    {
        $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);
        self::assertNotNull($session->record->getRawOriginal('tenant_id'));

        $request = Request::create('/refresh/sessions/current', 'POST', ['refresh_token' => $session->tokens->refreshToken?->reveal()], server: ['REMOTE_ADDR' => self::CLIENT_IP]);

        DeclaredCredential::refresh('members')->declareOn($request);

        app()->instance('request', $request);

        Auth::forgetGuards();

        $caller = $this->assertQueryBudget(4, 0, static fn (): ?Caller => Auth::caller());
        $again  = $this->assertQueryBudget(0, 0, static fn (): ?Caller => Auth::caller());

        self::assertSame($session->record->getKey(), $caller?->session?->getSessionIdentifier());
        self::assertSame($caller, $again);
    }

    /**
     * Register the session guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign the seeded identity in and return its session's refresh token.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function signedIn(): string
    {
        $token = $this->sessions()->signIn('password', self::credentials())->session?->tokens->refreshToken?->reveal();

        self::assertIsString($token);

        return $token;
    }

    /**
     * The `api` guard's session service, on a guard resolved afresh for a
     * sign-out request with the body and server values.
     *
     * @param  array<string, string>  $body
     * @param  array<string, string>  $server
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function serving(array $body, array $server = []): SessionService
    {
        app()->instance('request', Request::create('/auth/logout', 'POST', $body, server: ['REMOTE_ADDR' => self::CLIENT_IP, ...$server]));

        Auth::forgetGuards();

        return Auth::sessions('api');
    }
}
