<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Routing\CallerCredentials;
use SineMacula\Laravel\Authentication\Routing\DeclaredCredential;
use SineMacula\Laravel\Authentication\Routing\MeBinding;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMeBindings;
use Tests\Integration\Fixtures\MeMember;
use Tests\Integration\Fixtures\MeMembership;
use Tests\Integration\Fixtures\MeSession;

/**
 * Query-budget contracts for the `me` route binding: `me` with the access
 * credential reads nothing the guard has not read already; an explicit id is
 * the model's own lookup and nothing more; a refresh credential is proven once
 * for a request, however many parameters bind it; and a `me` child costs the
 * one check that it is within the parent's relationship.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MeBinding::class)]
#[CoversClass(CallerCredentials::class)]
final class MeBindingQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithMeBindings;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMeTables();
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
     * Once the guard has authenticated the bearer, `me` binds the member, its
     * membership and its session without a query, and an explicit session id
     * costs the session's own lookup alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMeWithTheAccessCredentialAddsNoQuery(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $another = $this->signedIn('ada@example.test');

        $this->bindRequestWithBearer('/members/me', $session->tokens->accessToken->reveal());

        Auth::forgetGuards();

        self::assertNotNull(Auth::guard(self::MEMBERS)->user());

        $unused = static fn (): never => self::fail('The lookup ran for me.');

        $bound = $this->assertQueryBudget(0, 0, static fn (): array => [
            MeBinding::current()->resolve(new MeMember, 'me', $unused),
            MeBinding::current()->resolve(new MeMembership, 'me', $unused),
            MeBinding::current()->resolve(new MeSession, 'me', $unused),
        ]);

        self::assertSame($session->record->getKey(), $bound[2]?->getKey());

        $id     = $another->record->getKey();
        $lookup = static fn (): ?Model => MeSession::query()->whereKey($id)->first();
        $value  = (string) IdentifierCoercion::stringify($id);
        $found  = $this->assertQueryBudget(1, 0, static fn (): ?Model => MeBinding::current()->resolve(new MeSession, $value, $lookup));

        self::assertSame($id, $found?->getKey());
    }

    /**
     * A refresh credential is proven by the first parameter that binds it,
     * reading the session, the member and its membership; a second binds
     * without a query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCredentialIsProvenOncePerRequest(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $body    = (string) json_encode(['refresh_token' => $session->tokens->refreshToken?->reveal()]);
        $request = Request::create('/refresh/sessions/me/me', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: $body);

        DeclaredCredential::refresh(null)->declareOn($request);

        app()->instance('request', $request);

        Auth::forgetGuards();

        $unused = static fn (): never => self::fail('The lookup ran for me.');

        $first = $this->assertQueryBudget(3, 0, static fn (): ?Model => MeBinding::current()->resolve(new MeSession, 'me', $unused));
        $again = $this->assertQueryBudget(0, 0, static fn (): ?Model => MeBinding::current()->resolve(new MeSession, 'me', $unused));

        self::assertSame($session->record->getKey(), $first?->getKey());
        self::assertSame($first, $again);
    }

    /**
     * A `me` child of the caller's own member is bound by one query, the check
     * that the session is within the member's relationship.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMeChildCostsOneQuery(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');

        $this->bindRequestWithBearer('/members/me/sessions/me', $session->tokens->accessToken->reveal());

        Auth::forgetGuards();

        self::assertNotNull(Auth::guard(self::MEMBERS)->user());

        $member = MeBinding::current()->resolve(new MeMember, 'me', static fn (): never => self::fail('The lookup ran for me.'));

        self::assertInstanceOf(MeMember::class, $member);

        $child = $this->assertQueryBudget(1, 0, static fn (): ?Model => $member->resolveChildRouteBinding('session', 'me', null));

        self::assertSame($session->record->getKey(), $child?->getKey());
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

        self::configureMeGuards($app->make(ConfigRepository::class));
    }
}
