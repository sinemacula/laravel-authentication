<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests for the active tenant through Laravel: a member signs in to a
 * tenant below its own when the application lets it, the session records it,
 * every token of the session names it and is held to it on each request,
 * `Auth::tenant()` is it, a refresh keeps it while the application still lets
 * the member act there, and deactivating it ends the session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(RefreshAdmission::class)]
#[CoversClass(TenantAdmission::class)]
final class ActiveTenantTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Tests\Fixtures\Tenancy\DescendantTenants The application's tree, bound as the tenant access and resolver. */
    private DescendantTenants $tree;

    /**
     * Freeze the clocks, create the tables, bind the tree and add a route that
     * reports the request's active tenant.
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

        $this->createSessionTables();

        $this->tree = new DescendantTenants;

        app()->instance(TenantAccess::class, $this->tree);
        app()->instance(TenantResolver::class, $this->tree);

        Route::middleware('auth:members')->get('/members/tenant', static fn (): array => ['tenant' => Auth::tenant()?->getTenantIdentifier()]);
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A sign-in that names a tenant below the member's own starts a session
     * acting in it: the row records its identifier, the token names it, the
     * request acts in it, and the guard bound by the sign-in reports it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInActsInTheTenantItSelects(): void
    {
        [$descendant, $session] = $this->signedInBelow();

        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), Session::query()->sole()->getTenantId());
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), $this->accessClaims($session)['tenant_id'] ?? null);
        self::assertTrue($descendant->is(Auth::manager()->guard('members')->tenant())); // @phpstan-ignore method.notFound

        $this->bearer($session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => $descendant->getKey()]);
    }

    /**
     * Without a resolver of the application's own, another tenant cannot be
     * found, and without its tenant access the member may not act in one: the
     * sign-in is refused as `tenant_ineligible` either way and nothing is
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTheApplicationDoesNotAllowIsRefusedAtSignIn(): void
    {
        [, , $own] = $this->seedMember();

        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        self::assertSame(FailureReason::TENANT_INELIGIBLE, $this->signInTo(TenantSelection::of($descendant->getKey()))->reason);

        $this->tree->place($descendant->getKey(), $own->getKey());

        app()->instance(TenantResolver::class, new ResolveNoTenant);

        self::assertSame(FailureReason::TENANT_INELIGIBLE, $this->signInTo(TenantSelection::of($descendant->getKey()))->reason);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * Each request checks only that the session's active tenant is still
     * active: the access contract is never asked, and the tenant is resolved
     * once per request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestAsksNoAccessContract(): void
    {
        [, $session] = $this->signedInBelow();

        $asked    = $this->tree->asked;
        $resolved = $this->tree->resolved;

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
        $this->bearer($session->tokens->accessToken->reveal())->assertOk();

        self::assertSame($asked, $this->tree->asked);
        self::assertSame($resolved + 2, $this->tree->resolved);
    }

    /**
     * The token is held to the session's active tenant on every request: one
     * whose session now acts in another tenant is refused as
     * `session_tenant_mismatch`, and one whose active tenant was deactivated,
     * or no longer resolves, as `tenant_inactive`; the member's own tenant must
     * stay active too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestIsHeldToTheSessionsActiveTenant(): void
    {
        [$descendant, $session, $own] = $this->signedInBelow();

        $this->recordEvents([AuthenticationFailed::class]);

        Session::query()->update(['tenant_id' => IdentifierCoercion::stringify($own->getKey())]);

        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        self::assertSame(FailureReason::SESSION_TENANT_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);

        Session::query()->update(['tenant_id' => IdentifierCoercion::stringify($descendant->getKey())]);

        foreach ([$descendant, $own] as $inactive) {

            $inactive->forceFill(['is_active' => false])->save();

            $this->recordEvents([AuthenticationFailed::class]);

            $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

            self::assertSame(FailureReason::TENANT_INACTIVE, $this->recordedEvent(AuthenticationFailed::class)->reason);

            $inactive->forceFill(['is_active' => true])->save();
        }

        $descendant->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A refresh keeps the session in its active tenant, issuing tokens that
     * name it, and asks the tenant access again: once the application no longer
     * lets the member act there, the refresh is refused as `tenant_ineligible`,
     * and the session is not revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshKeepsTheActiveTenantWhileTheAccessAllowsIt(): void
    {
        [$descendant, $session] = $this->signedInBelow();

        $refreshed = self::sessionsOf($this->freshGuard('members'))->refresh($session->tokens->refreshToken->reveal())->session;

        self::assertNotNull($refreshed);
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), $this->accessClaims($refreshed)['tenant_id'] ?? null);

        app()->instance(TenantAccess::class, new DescendantTenants);

        $refused = self::sessionsOf($this->freshGuard('members'))->refresh($refreshed->tokens->refreshToken->reveal());

        self::assertSame(FailureReason::TENANT_INELIGIBLE, $refused->reason);
        self::assertNull(Session::query()->sole()->getRevokedAt());
    }

    /**
     * Deactivating the session's active tenant ends the session, though the
     * member belongs to another tenant and is not listed, as
     * `tenant_deactivated`, reported with the tenant; a member's own session in
     * its own tenant is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeactivatingTheActiveTenantEndsItsSessions(): void
    {
        [$descendant, $session] = $this->signedInBelow();

        $this->seedMember('own@example.test');

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('own@example.test'))->isSignedIn());

        $this->recordEvents([SessionRevoked::class]);

        self::assertSame(1, $this->sessions('members')->tenantDeactivated($descendant, []));

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::TENANT_DEACTIVATED, $revoked->reason);
        self::assertSame($descendant, $revoked->context->tenant);
        self::assertSame($session->record->getKey(), $revoked->context->sessionId);
        self::assertSame(1, Session::query()->whereNull('revoked_at')->count());
    }

    /**
     * Configure the session guards.
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
     * Seed a member of a tenant, place another tenant below it, and sign the
     * member in to that one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenant, 1: \SineMacula\Laravel\Authentication\Sessions\SignedInSession, 2: \Tests\Integration\Fixtures\ActivatableTenant, 3: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function signedInBelow(): array
    {
        [, $membership, $own] = $this->seedMember();

        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        $this->tree->place($descendant->getKey(), $own->getKey());

        $session = $this->signInTo(TenantSelection::of($descendant->getKey()))->session;

        self::assertNotNull($session);
        self::assertInstanceOf(ActivatableTenantMembership::class, $membership);

        return [$descendant, $session, $own, $membership];
    }

    /**
     * Sign the seeded member in with the tenant selection.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInTo(TenantSelection $tenant): SignInResult
    {
        $context = new SignInContext(ClientContext::fromRequest(Request::create('/')), tenant: $tenant);

        return $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context);
    }

    /**
     * The claims of the session's access token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return array<string, mixed>
     */
    private function accessClaims(SignedInSession $session): array
    {
        return Auth::jwt('members')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS) ?? [];
    }

    /**
     * Send a request with the member's bearer token.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/members/tenant');
    }
}
