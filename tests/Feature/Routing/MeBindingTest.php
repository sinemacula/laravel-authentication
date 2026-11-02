<?php

declare(strict_types = 1);

namespace Tests\Feature\Routing;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Routing\CallerCredentials;
use SineMacula\Laravel\Authentication\Routing\MeBinding;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMeBindings;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MeMember;
use Tests\Integration\Fixtures\MeMembership;
use Tests\Integration\Fixtures\MeSession;
use Tests\TestCase;

/**
 * Feature tests of the `me` route binding, driven over HTTP through routes an
 * application registers with `Route::pattern()`: `me` binds the caller's own
 * member, session and membership from the bearer, the refresh credential or the
 * pending credential the route declares, and is a JSON `401` without one; any
 * other id binds only what agrees with that credential, through Eloquent's own
 * lookup (custom keys, soft deletes, scoped child bindings), and is a `404`
 * otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MeBinding::class)]
#[CoversClass(CallerCredentials::class)]
#[CoversTrait(ResolvesMeRouteBinding::class)]
final class MeBindingTest extends TestCase
{
    use InteractsWithMeBindings;

    /** @var string The id pattern of the members and sessions, both UUID-keyed, or `me`. */
    private const string UUID_OR_ME = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|me';

    /** @var string A cookie application over the same members, on the root path. */
    private const string BROWSERS = 'browsers';

    /** @var string The refresh cookie the cookie application derives on the root path. */
    private const string BROWSER_COOKIE = '__Host-browsers_refresh_token';

    /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\AuthenticationFailed> The failures reported since the test began. */
    private \ArrayObject $failures;

    /**
     * Create the tables, register the patterns and routes, and record every
     * failure reported.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMeTables();

        Route::pattern('member', self::UUID_OR_ME);
        Route::pattern('session', self::UUID_OR_ME);
        Route::pattern('oldSession', self::UUID_OR_ME);
        Route::pattern('membership', '[0-9]+|me');
        Route::pattern('principal', '[0-9]+|me');

        self::registerRoutes();

        $failures = new \ArrayObject;

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use ($failures): void {
            $failures->append($event);
        });

        $this->failures = $failures;
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMeTables();

        parent::tearDown();
    }

    /**
     * With a bearer, `me` binds the caller's own member, the session the token
     * names and the membership it acts as.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMeBindsTheCallersOwnInstancesFromTheBearer(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $token   = $session->tokens->accessToken->reveal();

        $this->bearer('GET', '/members/me', $token)->assertOk()->assertExactJson(['id' => $member->getKey()]);
        $this->bearer('GET', '/sessions/me', $token)->assertOk()->assertExactJson(['id' => $session->record->getKey()]);
        $this->bearer('GET', '/memberships/me', $token)->assertOk()->assertExactJson(['id' => $membership->getKey()]);
    }

    /**
     * With a bearer, an explicit id binds only what agrees with it: the
     * caller's own member (by key or by a custom key), any of its sessions, and
     * any membership the application admits for it; another member, another
     * member's session or membership, an unknown session and a soft-deleted
     * membership are each a `404`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExplicitIdBindsOnlyWhatAgreesWithTheBearer(): void
    {
        [$member, [$first, $second, $trashed]] = $this->seedMember('ada@example.test', 3);
        [$other, [$foreign]]                   = $this->seedMember('grace@example.test');

        $current = $this->signedIn('ada@example.test', $first);
        $another = $this->signedIn('ada@example.test', $first);
        $theirs  = $this->signedIn('grace@example.test');
        $token   = $current->tokens->accessToken->reveal();

        $trashed->delete();

        $this->bearer('GET', '/members/' . self::key($member), $token)->assertOk()->assertExactJson(['id' => $member->getKey()]);
        $this->bearer('GET', '/members/' . self::key($other), $token)->assertNotFound();
        $this->bearer('GET', '/by-email/ada@example.test', $token)->assertOk()->assertExactJson(['id' => $member->getKey()]);
        $this->bearer('GET', '/by-email/grace@example.test', $token)->assertNotFound();

        $this->bearer('GET', '/sessions/' . self::key($another->record), $token)->assertOk()->assertExactJson(['id' => $another->record->getKey()]);
        $this->bearer('GET', '/sessions/' . self::key($theirs->record), $token)->assertNotFound();
        $this->bearer('GET', '/sessions/' . Str::uuid(), $token)->assertNotFound();

        $this->bearer('GET', '/memberships/' . self::key($first), $token)->assertOk()->assertExactJson(['id' => $first->getKey()]);
        $this->bearer('GET', '/memberships/' . self::key($second), $token)->assertOk()->assertExactJson(['id' => $second->getKey()]);
        $this->bearer('GET', '/memberships/' . self::key($foreign), $token)->assertNotFound();
        $this->bearer('GET', '/trashed/memberships/' . self::key($trashed), $token)->assertNotFound();
    }

    /**
     * A soft-deleted session of the caller's member is bound only where the
     * route allows trashed models, top-level and as a scoped child.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASoftDeletedSessionIsBoundOnlyWhereTheRouteAllowsTrashedModels(): void
    {
        $this->seedMember('ada@example.test');

        $current = $this->signedIn('ada@example.test');
        $deleted = $this->signedIn('ada@example.test');
        $token   = $current->tokens->accessToken->reveal();
        $id      = self::key($deleted->record);

        $deleted->record->delete();

        $this->bearer('GET', '/sessions/' . $id, $token)->assertNotFound();
        $this->bearer('GET', '/trashed/sessions/' . $id, $token)->assertOk()->assertExactJson(['id' => $id]);
        $this->bearer('GET', '/members/me/sessions/' . $id, $token)->assertNotFound();
        $this->bearer('GET', '/trashed/members/me/sessions/' . $id, $token)->assertOk()->assertExactJson(['member' => $current->identity->getAuthIdentifier(), 'session' => $id]);
    }

    /**
     * Without a credential, `me` is a JSON `401` whatever the request accepts,
     * never a redirect, and an explicit id a `404`; nothing is reported.
     *
     * @return void
     */
    public function testMeWithoutACredentialIsAJson401AndAnExplicitIdA404(): void
    {
        $this->get('/open/sessions/me', ['Accept' => 'text/html'])->assertUnauthorized()->assertExactJson(['message' => 'Unauthenticated.']);
        $this->getJson('/open/members/me')->assertUnauthorized()->assertExactJson(['message' => 'Unauthenticated.']);
        $this->getJson('/open/sessions/' . Str::uuid())->assertNotFound();

        self::assertSame([], $this->failures());
    }

    /**
     * An access-only token names no session: its session `me` is a `401`, while
     * its member and membership still bind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionMeOfAnAccessOnlyTokenIsA401(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $token = Auth::jwt(self::MEMBERS)->issueAccessToken($member, $membership, null, null)->reveal();

        $this->bearer('GET', '/sessions/me', $token)->assertUnauthorized();
        $this->bearer('GET', '/members/me', $token)->assertOk()->assertExactJson(['id' => $member->getKey()]);
        $this->bearer('GET', '/memberships/me', $token)->assertOk()->assertExactJson(['id' => $membership->getKey()]);
    }

    /**
     * On a route that declares the refresh credential, `me` binds the session
     * the refresh token proves, its member and its membership, and a session id
     * binds only that very session, top-level and as a scoped child.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCredentialBindsOnlyTheSessionItProves(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $proven = $this->signedIn('ada@example.test');
        $other  = $this->signedIn('ada@example.test');
        $body   = ['refresh_token' => $proven->tokens->refreshToken?->reveal()];
        $id     = self::key($proven->record);

        $this->send('/refresh/sessions/me', $body)->assertOk()->assertExactJson(['id' => $id]);
        $this->send('/refresh/sessions/' . $id, $body)->assertOk()->assertExactJson(['id' => $id]);
        $this->send('/refresh/sessions/' . self::key($other->record), $body)->assertNotFound();
        $this->send('/refresh/members/me', $body)->assertOk()->assertExactJson(['id' => $member->getKey()]);
        $this->send('/refresh/memberships/me', $body)->assertOk()->assertExactJson(['id' => $membership->getKey()]);

        $this->send('/refresh/members/me/sessions/me', $body)->assertOk()->assertExactJson(['member' => $member->getKey(), 'session' => $id]);
        $this->send('/refresh/members/me/sessions/' . $id, $body)->assertOk()->assertExactJson(['member' => $member->getKey(), 'session' => $id]);
        $this->send('/refresh/members/me/sessions/' . self::key($other->record), $body)->assertNotFound();

        self::assertSame([], $this->failures());
    }

    /**
     * A refresh token that is refused binds nothing and is reported once, flow
     * `refresh`, without the token; a request that carries none is not
     * reported, and a bearer does not stand in for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRefreshCredentialIsReportedOnceAndBindsNothing(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');

        $this->send('/refresh/sessions/me', ['refresh_token' => 'not-a-refresh-token'])->assertUnauthorized();

        self::assertCount(1, $this->failures());
        self::assertSame(AuthenticationFlow::REFRESH, $this->failures()[0]->flow);
        self::assertSame(FailureReason::TOKEN_INVALID, $this->failures()[0]->reason);
        self::assertSame(self::MEMBERS, $this->failures()[0]->context->guard);
        self::assertStringNotContainsString('not-a-refresh-token', serialize($this->failures()[0]));

        $this->send('/refresh/sessions/me')->assertUnauthorized();
        $this->bearer('POST', '/refresh/sessions/me', $session->tokens->accessToken->reveal())->assertUnauthorized();

        self::assertCount(1, $this->failures());
    }

    /**
     * On a cookie application, the refresh credential is read from its cookie:
     * `me` binds the session the cookie proves and a session id binds only that
     * very session, reporting nothing; a cookie sent without the custom header
     * binds nothing and is reported once as a cross-site request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCookieBindsOnlyTheSessionItProves(): void
    {
        config()->set('auth.guards.' . self::BROWSERS, [
            'driver'        => 'jwt',
            'provider'      => 'me_members',
            'application'   => ['methods' => ['password']],
            'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/']],
        ]);

        Route::middleware(['authentication.refresh:' . self::BROWSERS, SubstituteBindings::class])
            ->post('/browser/sessions/{session}', static fn (MeSession $session): array => ['id' => $session->getKey()]);

        $this->seedMember('ada@example.test');

        $proven = $this->signedIn('ada@example.test', guard: self::BROWSERS);
        $other  = $this->signedIn('ada@example.test', guard: self::BROWSERS);
        $cookie = $proven->tokens->refreshCookie?->cookie()->getValue();
        $id     = self::key($proven->record);

        self::assertNull($proven->tokens->refreshToken);
        self::assertIsString($cookie);

        $this->fromCookie('/browser/sessions/me', $cookie)->assertOk()->assertExactJson(['id' => $id]);
        $this->fromCookie('/browser/sessions/' . $id, $cookie)->assertOk()->assertExactJson(['id' => $id]);
        $this->fromCookie('/browser/sessions/' . self::key($other->record), $cookie)->assertNotFound();
        $this->fromCookie('/browser/sessions/me', $cookie, sameSite: false)->assertUnauthorized();

        self::assertCount(1, $this->failures());
        self::assertSame(AuthenticationFlow::REFRESH, $this->failures()[0]->flow);
        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $this->failures()[0]->reason);
        self::assertSame(self::BROWSERS, $this->failures()[0]->context->guard);
        self::assertStringNotContainsString($cookie, serialize($this->failures()[0]));
    }

    /**
     * On a route that declares the pending credential for choosing, `me` binds
     * the pending session and its member, and a membership id binds one the
     * session offers for the choice, never another member's; the membership
     * `me` is a `401`, as the session acts as none yet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingCredentialBindsTheSessionItNamesForAnAllowedAction(): void
    {
        [$member, [$first, $second]] = $this->seedMember('ada@example.test', 2);
        [, [$foreign]]               = $this->seedMember('grace@example.test');

        $result = $this->memberSignIn('ada@example.test');

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);

        $body = ['pending_credential' => $result->credential?->reveal()];
        $id   = (string) IdentifierCoercion::stringify($result->pending->session->getSessionIdentifier());

        $this->send('/pending/sessions/me', $body)->assertOk()->assertExactJson(['id' => $id]);
        $this->send('/pending/sessions/' . $id, $body)->assertOk()->assertExactJson(['id' => $id]);
        $this->send('/pending/members/me', $body)->assertOk()->assertExactJson(['id' => $member->getKey()]);
        $this->send('/pending/members/me/sessions/me', $body)->assertOk()->assertExactJson(['member' => $member->getKey(), 'session' => $id]);
        $this->send('/pending/principals/' . self::key($first), $body)->assertOk()->assertExactJson(['id' => $first->getKey()]);
        $this->send('/pending/principals/' . self::key($second), $body)->assertOk()->assertExactJson(['id' => $second->getKey()]);
        $this->send('/pending/principals/' . self::key($foreign), $body)->assertNotFound();
        $this->send('/pending/principals/me', $body)->assertUnauthorized();

        self::assertSame([], $this->failures());
    }

    /**
     * A pending credential binds nothing on a route of an action its session
     * does not allow now, reported once as `pending_action_not_allowed` with
     * the session; an unknown one is reported as `pending_invalid`; and one in
     * the query string, or none, is not read and not reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingCredentialIsRefusedForAnActionItsSessionDoesNotAllow(): void
    {
        [$member] = $this->seedMember('ada@example.test', 2);

        $result = $this->memberSignIn('ada@example.test');

        self::assertNotNull($result->pending);

        $credential = (string) $result->credential?->reveal();

        $this->send('/verify/sessions/me', ['pending_credential' => $credential])->assertUnauthorized();

        self::assertCount(1, $this->failures());
        self::assertSame(AuthenticationFlow::SIGN_IN, $this->failures()[0]->flow);
        self::assertSame(FailureReason::PENDING_ACTION_NOT_ALLOWED, $this->failures()[0]->reason);
        self::assertSame($member->getKey(), $this->failures()[0]->context->identity?->getAuthIdentifier());
        self::assertSame($result->pending->session->getSessionIdentifier(), $this->failures()[0]->context->session?->getSessionIdentifier());

        $this->send('/pending/sessions/me', ['pending_credential' => 'not-a-pending-credential'])->assertUnauthorized();

        self::assertCount(2, $this->failures());
        self::assertSame(AuthenticationFlow::SIGN_IN, $this->failures()[1]->flow);
        self::assertSame(FailureReason::PENDING_INVALID, $this->failures()[1]->reason);
        self::assertNull($this->failures()[1]->context->identity);

        $this->send('/pending/sessions/me?pending_credential=' . urlencode($credential))->assertUnauthorized();
        $this->send('/pending/sessions/me')->assertUnauthorized();

        self::assertCount(2, $this->failures());

        foreach ($this->failures() as $failure) {
            self::assertStringNotContainsString($credential, serialize($failure));
        }
    }

    /**
     * While a further factor is outstanding the pending credential binds for
     * verifying it, not for choosing a principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhileAFactorIsOutstandingThePendingCredentialBindsOnlyForVerifying(): void
    {
        $this->seedMember('ada@example.test', 2);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $result = $this->memberSignIn('ada@example.test');

        self::assertNotNull($result->pending);

        $body = ['pending_credential' => $result->credential?->reveal()];

        $this->send('/verify/sessions/me', $body)->assertOk()->assertExactJson(['id' => $result->pending->session->getSessionIdentifier()]);
        $this->send('/pending/sessions/me', $body)->assertUnauthorized();

        self::assertCount(1, $this->failures());
        self::assertSame(FailureReason::PENDING_ACTION_NOT_ALLOWED, $this->failures()[0]->reason);
    }

    /**
     * As a scoped child of the caller's member, a session binds only one of
     * the member's own, `me` the bearer's, and a membership one the member
     * may use; a child of another member is a `404`, as the parent is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScopedChildBindsWithinTheCallersMember(): void
    {
        [$member, [$first, $second]] = $this->seedMember('ada@example.test', 2);
        [$other]                     = $this->seedMember('grace@example.test');

        $current = $this->signedIn('ada@example.test', $first);
        $another = $this->signedIn('ada@example.test', $second);
        $theirs  = $this->signedIn('grace@example.test');
        $token   = $current->tokens->accessToken->reveal();
        $key     = $member->getKey();

        $this->bearer('GET', '/members/me/sessions/me', $token)->assertOk()->assertExactJson(['member' => $key, 'session' => $current->record->getKey()]);
        $another = self::key($another->record);

        $this->bearer('GET', '/members/me/sessions/' . $another, $token)->assertOk()->assertExactJson(['member' => $key, 'session' => $another]);
        $this->bearer('GET', '/members/me/sessions/' . self::key($theirs->record), $token)->assertNotFound();
        $this->bearer('GET', '/members/' . self::key($other) . '/sessions/me', $token)->assertNotFound();
        $this->bearer('GET', '/members/me/principals/me', $token)->assertOk()->assertExactJson(['member' => $key, 'principal' => $first->getKey()]);
        $this->bearer('GET', '/members/me/principals/' . self::key($second), $token)->assertOk()->assertExactJson(['member' => $key, 'principal' => $second->getKey()]);
    }

    /**
     * A `me` child must also be within the parent's relationship: the caller's
     * own session is a `404` through a relationship that leaves it out, and
     * binds once the relationship holds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMeChildOutsideTheParentsRelationshipIsAMiss(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $token   = $session->tokens->accessToken->reveal();
        $id      = self::key($session->record);

        $this->bearer('GET', '/members/me/old-sessions/me', $token)->assertNotFound();
        $this->bearer('GET', '/members/me/old-sessions/' . $id, $token)->assertNotFound();

        MeSession::query()->whereKey($id)->update(['client_name' => MeMember::OLD_CLIENT]);

        $this->bearer('GET', '/members/me/old-sessions/me', $token)->assertOk()->assertExactJson(['member' => $session->identity->getAuthIdentifier(), 'session' => $id]);
    }

    /**
     * A token of another application over the same members binds only on a
     * route of that application: `me` is the caller there and a `401` on this
     * one's routes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialBindsOnlyForItsOwnApplication(): void
    {
        [$member] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test', guard: self::OTHERS);
        $token   = $session->tokens->accessToken->reveal();

        $this->bearer('GET', '/open/members/me', $token)->assertUnauthorized();
        $this->bearer('GET', '/others/members/me', $token)->assertOk()->assertExactJson(['id' => $member->getKey()]);
    }

    /**
     * A model that is not a session, an identity or a principal is refused, for
     * `me` and any other value alike, before its lookup runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelOfNoKindIsRefused(): void
    {
        $model = new class extends Model {};

        try {
            MeBinding::current()->resolve($model, 'me', static fn (): never => self::fail('The lookup ran.'));

            self::fail('A model of no kind was bound.');
        } catch (\LogicException $exception) {
            self::assertSame('The me route binding binds a session, an identity or a principal; ' . $model::class . ' is none.', $exception->getMessage());
        }

        $this->expectException(\LogicException::class);

        MeBinding::current()->resolve($model, '1', static fn (): never => self::fail('The lookup ran.'));
    }

    /**
     * A child whose model does not use the trait is the parent's own lookup,
     * `me` included, unchanged; a lookup that finds no model is a miss.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChildOfAModelWithoutTheTraitIsTheParentsOwnLookup(): void
    {
        $found   = new IntegrationIdentity;
        $binding = MeBinding::current();

        self::assertSame($found, $binding->resolveChild(IntegrationIdentity::query(), 'me', static fn (): IntegrationIdentity => $found));
        self::assertNull($binding->resolveChild(IntegrationIdentity::query(), 'me', static fn (): string => 'not a model'));
        self::assertSame([], $this->failures());
    }

    /**
     * `me` binds the caller's own instance only when it is one of the model's
     * class: for a session model the caller's session is not an instance of, it
     * is an `AuthenticationException` for the route's guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMeOfAModelTheCallersInstanceIsNotOfIsAnAuthenticationFailure(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');

        $this->bearerRequest($session->tokens->accessToken->reveal());

        self::assertSame($session->record->getKey(), MeBinding::current()->resolve(new MeSession, 'me', static fn (): never => self::fail('The lookup ran.'))?->getKey());

        try {
            MeBinding::current()->resolve(new class extends Session {}, 'me', static fn (): never => self::fail('The lookup ran.'));

            self::fail('The caller\'s session was bound as a model of another class.');
        } catch (AuthenticationException $exception) {
            self::assertSame([self::MEMBERS], $exception->guards());
            self::assertSame('Unauthenticated.', $exception->getMessage());
        }
    }

    /**
     * Any other value runs the model's own lookup only for a request with a
     * caller, and binds what it finds only when it is of the model's class.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLookupRunsOnlyForACallerAndMustFindTheModelsClass(): void
    {
        [$member] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');

        app()->instance('request', Request::create('/sessions/1'));

        Auth::forgetGuards();

        self::assertNull(MeBinding::current()->resolve(new MeSession, self::key($session->record), static fn (): never => self::fail('The lookup ran without a caller.')));

        $this->bearerRequest($session->tokens->accessToken->reveal());

        self::assertNull(MeBinding::current()->resolve(new MeSession, self::key($session->record), static fn (): MeMember => $member));
        $record = $session->record;
        $lookup = static fn (): ?MeSession => MeSession::query()->whereKey($record->getKey())->first();

        self::assertSame($record->getKey(), MeBinding::current()->resolve(new MeSession, self::key($record), $lookup)?->getKey());
    }

    /**
     * The binding is made through the package's auth manager: another bound as
     * `auth` is a misconfiguration.
     *
     * @return void
     */
    public function testTheBindingNeedsThePackagesAuthManager(): void
    {
        app()->instance('auth', new IlluminateAuthManager(app()));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The me route binding needs the package\'s auth manager as `auth`; ' . IlluminateAuthManager::class . ' is bound.');

        MeBinding::current();
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

        self::configureMeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Register the routes: behind `auth:members` for the bearer, declaring the
     * refresh or the pending credential, and without any credential.
     *
     * @return void
     */
    private static function registerRoutes(): void
    {
        $id     = static fn (Model $model): array => ['id' => $model->getKey()];
        $nested = static fn (MeMember $member, MeSession $session): array => ['member' => $member->getKey(), 'session' => $session->getKey()];

        $membership = static fn (MeMember $member, MeMembership $principal): array => ['member' => $member->getKey(), 'principal' => $principal->getKey()];

        Route::middleware(['auth:' . self::MEMBERS, SubstituteBindings::class])->group(static function () use ($id, $nested, $membership): void {
            Route::get('/members/{member}', static fn (MeMember $member): array => $id($member));
            Route::get('/by-email/{person:email}', static fn (MeMember $person): array => $id($person));
            Route::get('/sessions/{session}', static fn (MeSession $session): array => $id($session));
            Route::get('/trashed/sessions/{session}', static fn (MeSession $session): array => $id($session))->withTrashed();
            Route::get('/memberships/{membership}', static fn (MeMembership $membership): array => $id($membership));
            Route::get('/trashed/memberships/{membership}', static fn (MeMembership $membership): array => $id($membership))->withTrashed();
            Route::get('/members/{member}/sessions/{session}', static fn (MeMember $member, MeSession $session): array => $nested($member, $session))->scopeBindings();
            Route::get('/trashed/members/{member}/sessions/{session}', static fn (MeMember $member, MeSession $session): array => $nested($member, $session))
                ->scopeBindings()
                ->withTrashed();
            Route::get('/members/{member}/old-sessions/{oldSession}', static fn (MeMember $member, MeSession $oldSession): array => $nested($member, $oldSession))
                ->scopeBindings();
            Route::get('/members/{member}/principals/{principal}', static fn (MeMember $member, MeMembership $principal): array => $membership($member, $principal))
                ->scopeBindings();
        });

        Route::middleware(['auth:' . self::OTHERS, SubstituteBindings::class])->get('/others/members/{member}', static fn (MeMember $member): array => $id($member));

        Route::middleware(SubstituteBindings::class)->group(static function () use ($id): void {
            Route::get('/open/members/{member}', static fn (MeMember $member): array => $id($member));
            Route::get('/open/sessions/{session}', static fn (MeSession $session): array => $id($session));
        });

        Route::middleware(['authentication.refresh:' . self::MEMBERS, SubstituteBindings::class])->prefix('/refresh')->group(static function () use ($id, $nested): void {
            Route::post('/members/{member}', static fn (MeMember $member): array => $id($member));
            Route::post('/sessions/{session}', static fn (MeSession $session): array => $id($session));
            Route::post('/memberships/{membership}', static fn (MeMembership $membership): array => $id($membership));
            Route::post('/members/{member}/sessions/{session}', static fn (MeMember $member, MeSession $session): array => $nested($member, $session))->scopeBindings();
        });

        $pending = Route::middleware(['authentication.pending:choose_principal,' . self::MEMBERS, SubstituteBindings::class])->prefix('/pending');

        $pending->group(static function () use ($id, $nested): void {
            Route::post('/members/{member}', static fn (MeMember $member): array => $id($member));
            Route::post('/sessions/{session}', static fn (MeSession $session): array => $id($session));
            Route::post('/principals/{membership}', static fn (MeMembership $membership): array => $id($membership));
            Route::post('/members/{member}/sessions/{session}', static fn (MeMember $member, MeSession $session): array => $nested($member, $session))->scopeBindings();
        });

        Route::middleware(['authentication.pending:mfa.verify', SubstituteBindings::class])
            ->post('/verify/sessions/{session}', static fn (MeSession $session): array => $id($session));
    }

    /**
     * Bind a request that carries the access token, on guards resolved afresh.
     *
     * @param  string  $token
     * @return void
     */
    private function bearerRequest(#[\SensitiveParameter] string $token): void
    {
        app()->instance('request', Request::create('/bound', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        Auth::forgetGuards();
    }

    /**
     * The failures reported since the test began, in order.
     *
     * @return list<\SineMacula\Laravel\Authentication\Events\AuthenticationFailed>
     */
    private function failures(): array
    {
        return array_values($this->failures->getArrayCopy());
    }

    /**
     * The model's key as a route segment.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function key(Model $model): string
    {
        return (string) IdentifierCoercion::stringify($model->getKey());
    }

    /**
     * Send a JSON post with the body, on guards resolved afresh.
     *
     * @param  string  $uri
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function send(string $uri, #[\SensitiveParameter] array $body = []): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson($uri, $body);
    }

    /**
     * Send a JSON post carrying the refresh cookie of the cookie application,
     * from the API's own origin and with the custom header unless it is to look
     * cross-site, on guards resolved afresh.
     *
     * @param  string  $uri
     * @param  string  $cookie
     * @param  bool  $sameSite
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function fromCookie(string $uri, #[\SensitiveParameter] string $cookie, bool $sameSite = true): TestResponse
    {
        Auth::forgetGuards();

        $headers = $sameSite ? ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'] : ['Origin' => 'http://localhost'];

        return $this->withCredentials()->withUnencryptedCookie(self::BROWSER_COOKIE, $cookie)->postJson($uri, [], $headers);
    }

    /**
     * Send the request with the access token, on guards resolved afresh.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $method, string $uri, #[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->json($method, $uri, [], ['Authorization' => 'Bearer ' . $token]);
    }
}
