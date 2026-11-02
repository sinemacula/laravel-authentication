<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AccessOnlyIdentity;
use Tests\Integration\Fixtures\ForeignModelSessionsIdentity;
use Tests\TestCase;

/**
 * Feature tests of a session list route an application registers behind
 * `auth:api`, driven over HTTP: `Auth::sessions('api')->sessions()` lists the
 * signed-in identity's active sessions of every guard, marks the one the
 * request is authenticated with, pages them, and never exposes a digest,
 * revocation column, owner or principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(ActiveSessions::class)]
#[CoversClass(SessionSummary::class)]
final class ActiveSessionsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<string> The keys of a summary, in order. */
    private const array SUMMARY_KEYS = [
        'id',
        'guard',
        'sign_in_method',
        'client_name',
        'platform',
        'created_at',
        'created_ip',
        'created_user_agent',
        'signed_in_at',
        'last_used_at',
        'last_used_ip',
        'last_used_user_agent',
        'idle_expires_at',
        'absolute_expires_at',
        'current',
    ];

    /**
     * Create the tables and register the session list route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/sessions', static function (): LengthAwarePaginator {

            $identity = Auth::identity();

            assert($identity instanceof Identity);

            return Auth::sessions('api')->sessions($identity, request()->integer('per_page', 15));
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
     * The list holds the identity's sessions of every guard, marks only the
     * session the request's access token names, and shows each without its
     * digests, revocation, owner or principal.
     *
     * @return void
     */
    public function testListsEveryGuardsSessionsAndMarksTheCurrentOne(): void
    {
        $this->seedIdentity();
        $this->seedIdentity('grace@example.test');

        $phone  = $this->signIn('api', 'Phone');
        $laptop = $this->signIn('api', 'Laptop');
        $admin  = $this->signIn('admin', 'Console');

        $this->signIn('api', 'Other', 'grace@example.test');

        $response = $this->list($laptop->tokens->accessToken->reveal())->assertOk();

        $response->assertJsonCount(3, 'data')->assertJsonPath('total', 3);

        /** @var list<array<string, mixed>> $rows */
        $rows = $response->json('data');

        $current = array_filter($rows, static fn (array $row): bool => $row['current'] === true);

        self::assertEqualsCanonicalizing([self::idOf($phone), self::idOf($laptop), self::idOf($admin)], array_column($rows, 'id'));
        self::assertSame([self::idOf($laptop)], array_column($current, 'id'));

        foreach ($rows as $row) {
            self::assertSame(self::SUMMARY_KEYS, array_keys($row));
        }

        $console = array_values(array_filter($rows, static fn (array $row): bool => $row['client_name'] === 'Console'))[0];

        self::assertSame('admin', $console['guard']);
        self::assertSame('password', $console['sign_in_method']);
        self::assertSame(self::CLIENT_IP, $console['created_ip']);
        self::assertSame(self::CLIENT_AGENT, $console['created_user_agent']);
        $json = (string) json_encode($rows);

        self::assertStringNotContainsString($laptop->tokens->refreshToken?->reveal(), $json);
        self::assertStringNotContainsString((string) $laptop->record->getRefreshKey(), $json);
    }

    /**
     * A session revoked, past a deadline or pending is not listed.
     *
     * @return void
     */
    public function testRevokedEndedAndPendingSessionsAreNotListed(): void
    {
        $this->seedIdentity();

        $current = $this->signIn('api', 'Phone');
        $revoked = $this->signIn('api', 'Revoked');
        $ended   = $this->signIn('api', 'Ended');
        $pending = $this->signIn('api', 'Pending');

        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);
        Session::query()->whereKey($ended->record->getKey())->update(['idle_expires_at' => now()]);
        Session::query()->whereKey($pending->record->getKey())->update(['status' => 'pending', 'requires' => '["mfa"]']);

        $this->list($current->tokens->accessToken->reveal())->assertOk()->assertJsonCount(1, 'data')->assertJsonPath('data.0.client_name', 'Phone');
    }

    /**
     * The page size and the request's `page` parameter page the list.
     *
     * @return void
     */
    public function testPagesTheList(): void
    {
        $this->seedIdentity();

        $first = $this->signIn('api', 'One');

        $this->signIn('api', 'Two');
        $this->signIn('api', 'Three');

        $this->list($first->tokens->accessToken->reveal(), '?per_page=2&page=2')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('total', 3)
            ->assertJsonPath('per_page', 2)
            ->assertJsonPath('current_page', 2);
    }

    /**
     * A session bound to the guard is the current one only when it is of the
     * listed session's class as well as its identifier: a session of another
     * class that shares the identifier marks none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundSessionOfAnotherClassWithTheSameIdentifierIsNotCurrent(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn('api', 'Phone');
        $guard    = $this->freshGuard();

        $guard->authenticateAs($session->identity, $session->principal, $session->record);

        self::assertTrue(self::sessionsOf($guard)->sessions($identity)->items()[0]->current);

        $other = new class extends Session {};
        $other->setRawAttributes($session->record->getAttributes(), true);
        $other->exists = true;

        $guard->authenticateAs($session->identity, $session->principal, $other);

        $listed = self::sessionsOf($guard)->sessions($identity)->items();

        self::assertSame([self::idOf($session)], array_map(static fn (SessionSummary $summary): string => $summary->id, $listed));
        self::assertFalse($listed[0]->current);
    }

    /**
     * An explicit page wins over the request's, and the default page size is
     * 15.
     *
     * @return void
     */
    public function testAnExplicitPageWinsAndFifteenIsTheDefaultSize(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn('api', 'One');

        $sessions = $this->sessions();

        app('request')->query->set('page', '2');

        self::assertSame(2, $sessions->sessions($identity)->currentPage());

        $page = $sessions->sessions($identity, page: 1);

        self::assertSame(1, $page->currentPage());
        self::assertSame(15, $page->perPage());
        self::assertCount(1, $page->items());
        self::assertFalse($page->items()[0]->current);
    }

    /**
     * Rows of a page size outside 1 to 100.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedPageSizes(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        yield 'over a hundred' => [101];
    }

    /**
     * A page size outside 1 to 100 is refused before anything is read.
     *
     * @param  int  $perPage
     * @return void
     */
    #[DataProvider('provideRefusedPageSizes')]
    public function testRefusesAPageSizeOutsideOneToAHundred(int $perPage): void
    {
        $identity = $this->seedIdentity();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Sessions are listed 1 to 100 to a page; {$perPage} were asked for.");

        $this->sessions()->sessions($identity, $perPage);
    }

    /**
     * Both ends of the page size are accepted.
     *
     * @return void
     */
    public function testAcceptsOneAndAHundredToAPage(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn('api', 'One');
        $this->signIn('api', 'Two');

        self::assertCount(1, $this->sessions()->sessions($identity, 1)->items());
        self::assertCount(2, $this->sessions()->sessions($identity, 100)->items());
    }

    /**
     * An identity that holds no sessions has no list: a misconfiguration.
     *
     * @return void
     */
    public function testRefusesAnIdentityWithoutSessions(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only identities that implement ' . HasSessions::class . ' have sessions to list; ' . AccessOnlyIdentity::class . ' does not.');

        $this->sessions()->sessions(new AccessOnlyIdentity);
    }

    /**
     * A `sessions()` relation over a model that is not a session is a
     * misconfiguration.
     *
     * @return void
     */
    public function testRefusesASessionsRelationOverAnotherModel(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The sessions() relation of ' . ForeignModelSessionsIdentity::class . ' must query a model that implements ' . EloquentSession::class . '.');

        $this->sessions()->sessions(new ForeignModelSessionsIdentity);
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
        $sessions = $this->sessions($guard);
        $session  = $sessions->signIn('password', self::credentials($email), SignInContext::fromRequest(app('request'), clientName: $client))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The identifier of the session, as the list shows it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function idOf(SignedInSession $session): string
    {
        return (string) IdentifierCoercion::stringify($session->record->getSessionIdentifier());
    }

    /**
     * Ask the session list route for the list, with the access token.
     *
     * @param  string  $token
     * @param  string  $query
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function list(#[\SensitiveParameter] string $token, string $query = ''): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/sessions' . $query);
    }
}
