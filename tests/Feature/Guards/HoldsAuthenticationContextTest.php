<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\Concerns\HoldsAuthenticationContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Context\ScriptedContributor;
use Tests\TestCase;
use Tests\Unit\Stubs\StubRequestResolvingGuard;

/**
 * Feature tests for the authentication context a guard builds, holds and
 * forgets.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HoldsAuthenticationContext::class)]
final class HoldsAuthenticationContextTest extends TestCase
{
    use InteractsWithSessions;

    /** @var int Reads of the proofs table since counting began. */
    private int $proofReads = 0;

    /**
     * Freeze the clocks and create the tables.
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
     * A request without a credential has no context, and neither has an
     * identity a guard bound without a principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuestHasNoContext(): void
    {
        self::assertNull($this->freshGuard()->authenticationContext());

        $identity = $this->seedIdentity();
        $provider = Auth::createUserProvider('identities');

        self::assertInstanceOf(IdentityProvider::class, $provider);

        $guard = new StubRequestResolvingGuard('api', $provider, app(PrincipalResolver::class), app('events'), request(), new Timebox);

        $guard->resolvable = $identity;

        self::assertNull($guard->authenticationContext());
        self::assertTrue($guard->hasUser());
    }

    /**
     * The context is built on the first ask, reading the session's proofs once,
     * and held after.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextIsBuiltOnceAndHeld(): void
    {
        $guard = $this->bearerGuard($this->signedIn());

        $this->countProofReads();

        $first = $guard->authenticationContext();

        self::assertNotNull($first);
        self::assertSame('access_token', $first->credential?->value);
        self::assertSame($first, $guard->authenticationContext());
        self::assertSame(1, $this->proofReads);
    }

    /**
     * Rows of `[change, authenticated, credential]`: each change to the bound
     * state and what the guard holds after it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Guards\JwtGuard, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): void, 1: bool, 2: ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChanges(): iterable
    {
        $kept = CredentialKind::ACCESS_TOKEN;

        yield 'setPrincipal()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->setPrincipal($in->principal);
        }, true, $kept];
        yield 'setSession()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->setSession($in->record);
        }, true, $kept];
        yield 'login()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->login($in->identity, $in->principal, $in->record);
        }, true, null];
        yield 'setUser()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->setUser($in->identity);
        }, true, null];
        yield 'authenticateAs()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->authenticateAs($in->identity, $in->principal, $in->record);
        }, true, null];
        yield 'forgetUser()' => [static function (JwtGuard $guard): void {
            $guard->forgetUser();
        }, false, null];
        yield 'forgetSession()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->forgetSession($in->record);
        }, false, null];
        yield 'forgetIdentity()' => [static function (JwtGuard $guard, SignedInSession $in): void {
            $guard->forgetIdentity($in->identity);
        }, false, null];
        yield 'setRequest()' => [static function (JwtGuard $guard): void {
            $guard->setRequest(Request::create('/next'));
        }, false, null];
    }

    /**
     * Every change to the bound state forgets the context, which is rebuilt for
     * what is bound now.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Guards\JwtGuard, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): void  $change
     * @param  bool  $authenticated
     * @param  ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind  $credential
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChanges')]
    public function testEveryChangeToTheBoundStateForgetsTheContext(\Closure $change, bool $authenticated, ?CredentialKind $credential): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);
        $before   = $guard->authenticationContext();

        self::assertNotNull($before);

        $change($guard, $signedIn);

        $after = $guard->authenticationContext();

        if (!$authenticated) {
            self::assertNull($after);

            return;
        }

        self::assertNotNull($after);
        self::assertNotSame($before, $after);
        self::assertSame($credential, $after->credential);
    }

    /**
     * Forgetting the context for the bound session keeps the binding; for any
     * other session it does nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingTheContextKeepsTheBindingAndTouchesOnlyItsSession(): void
    {
        $signedIn = $this->signedIn();
        $other    = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($other);

        $guard  = $this->bearerGuard($signedIn);
        $before = $guard->authenticationContext();

        $guard->forgetAuthenticationContext($other->record);

        self::assertSame($before, $guard->authenticationContext());

        $guard->forgetAuthenticationContext($signedIn->record);

        $after = $guard->authenticationContext();

        self::assertNotNull($after);
        self::assertNotSame($before, $after);
        self::assertEquals($before, $after);
        self::assertSame($signedIn->identity->getAuthIdentifier(), $guard->id());

        $unresolved = $this->bearerGuard($signedIn);

        $unresolved->forgetAuthenticationContext($signedIn->record);

        self::assertFalse($unresolved->hasUser());
    }

    /**
     * A contributor that asks for the context while it is built is refused, and
     * the guard can still build it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContributorAskingForTheContextIsRefused(): void
    {
        $asked = 0;

        app()->instance('tests.context.audit', new ScriptedContributor(static function () use (&$asked): array {
            return ++$asked === 1 ? ['nested' => Auth::context()?->application] : ['nested' => null];
        }));

        app(ContextContributors::class)->register('audit', 'tests.context.audit');

        $guard = $this->bearerGuard($this->signedIn());

        Auth::shouldUse('api');

        try {
            $guard->authenticationContext();
            self::fail('The contributor was given the context being built.');
        } catch (\LogicException $exception) {
            self::assertSame('Guard [api] was asked for its authentication context while building it: a contributor must not ask.', $exception->getMessage());
        }

        self::assertSame(['nested' => null], $guard->authenticationContext()?->contributed['audit']);
        self::assertSame(2, $asked);
    }

    /**
     * A trusted bind whose session records a tenant that cannot be loaded
     * throws as `tenant()` does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeLoadedThrows(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);

        $tenant->delete();

        $guard = $this->freshGuard('members');

        $guard->login($member, $membership, $session->record);

        $this->expectException(TenantUnavailableException::class);

        $guard->authenticationContext();
    }

    /**
     * Register the guards and providers.
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
     * A session the identity signed in to with its password now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * A fresh `api` guard on a request bearing the session's access token, not
     * resolved yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearerGuard(SignedInSession $session): JwtGuard
    {
        app()->instance('request', Request::create('/context', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]));

        Auth::forgetGuards();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }

    /**
     * Count the reads of the proofs table from now on.
     *
     * @return void
     */
    private function countProofReads(): void
    {
        $this->proofReads = 0;

        DB::listen(function (QueryExecuted $query): void {

            if (!str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, 'authentication_proofs')) {
                return;
            }

            $this->proofReads++;
        });
    }
}
