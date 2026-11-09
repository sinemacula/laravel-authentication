<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Concerns\LooksUpSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests of the routes an application registers behind its guard to show
 * one of the signed-in identity's sessions or principals, driven over HTTP:
 * `Auth::sessions('api')->session()` answers the session's summary, marked when
 * it is the one the request is authenticated with, and nothing for a session
 * that is another identity's or no longer active; and
 * `Auth::sessions('members')->principal()` answers one of the principals the
 * identity may use the application as, and nothing for another identity's or
 * one no longer admitted; and `Auth::sessions('api')->proofs()` and
 * `firstFactor()` answer the counting proofs and first factor, and
 * `provenance()` the provenance, of any of the guard's active sessions, named
 * by key or given as the instance while its key still holds it, and nothing for
 * one of another guard, revoked or pending.
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
    use InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

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

        Route::middleware('auth:members')->get('/principals/{principal}', static function (string $principal): array {

            $identity = Auth::identity();

            assert($identity instanceof Identity);

            $found = Auth::sessions('members')->principal($identity, $principal, Auth::session()?->getSignInIdentifierType());

            return $found === null ? abort(404) : ['id' => $found->getPrincipalIdentifier()];
        });

        Route::middleware('auth:api')->get('/sessions/{session}/proofs', static function (Request $request, string $session): array {

            $kinds    = $request->filled('kinds') ? array_map(ProofKind::from(...), explode(',', $request->string('kinds')->value())) : null;
            $since    = $request->filled('since') ? CarbonImmutable::createFromTimestamp($request->integer('since')) : null;
            $sessions = Auth::sessions('api');

            return ['proofs' => $sessions->proofs($session, $since, $kinds), 'first_factor' => $sessions->firstFactor($session)];
        });

        Route::middleware('auth:api')->get('/session/proofs', static function (): array {

            $sessions = Auth::sessions('api');

            return ['proofs' => $sessions->proofs(Auth::session()), 'first_factor' => $sessions->firstFactor(Auth::session())];
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
        CarbonImmutable::setTestNow();

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

        $current = $this->show($laptop->tokens->accessToken->reveal(), self::idOf($laptop))->assertOk();

        self::assertSame(array_keys(SessionSummary::of($laptop->record, true)->toArray()), array_keys((array) $current->json()));

        $current->assertJsonPath('id', self::idOf($laptop))->assertJsonPath('client_name', 'Laptop')->assertJsonPath('current', true);

        $this->show($laptop->tokens->accessToken->reveal(), self::idOf($phone))->assertOk()->assertJsonPath('client_name', 'Phone')->assertJsonPath('current', false);
        $this->show($laptop->tokens->accessToken->reveal(), self::idOf($admin))->assertOk()->assertJsonPath('guard', 'admin')->assertJsonPath('current', false);
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
            $this->show($current->tokens->accessToken->reveal(), self::idOf($session))->assertNotFound();
        }
    }

    /**
     * The route answers the request's own session's counting proofs, the
     * step-up newest, then its first factor, narrowed by kind and by time, and
     * another identity's active session of the guard alike, since no identity
     * is checked; once the session is refreshed, the proofs hold none of its
     * tokens and neither of its refresh digests.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnswersAnActiveSessionsProofsAndFirstFactor(): void
    {
        $signedInAt = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($signedInAt);

        $identity = $this->seedIdentity();

        $this->seedIdentity('grace@example.test');

        $current   = $this->signIn('api', 'Phone');
        $other     = $this->signIn('api', 'Other', 'grace@example.test');
        $refreshed = $this->sessions()->refresh(PresentedRefreshToken::fromBody((string) $current->tokens->refreshToken?->reveal()), self::requestClient())->session;

        self::assertNotNull($refreshed);

        $token = $refreshed->tokens->accessToken->reveal();

        CarbonImmutable::setTestNow($signedInAt->addMinute());

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($identity, 'api', $current->record->getKey()), self::requestClient())->isIssued());

        $all = $this->proofsOf($token, self::idOf($current))->assertOk();

        self::assertSame(['additional_factor', 'first_factor'], array_column((array) $all->json('proofs'), 'kind'));
        self::assertSame(['factor-1', null], array_column((array) $all->json('proofs'), 'factor'));

        $all->assertJsonPath('first_factor.kind', 'first_factor')->assertJsonPath('first_factor.method', 'password');

        $body = (string) json_encode($all->json());

        foreach (['refresh_key', 'previous_refresh_key'] as $digest) {
            $stored = Session::query()->whereKey($current->record->getKey())->value($digest);

            self::assertIsString($stored);
            self::assertNotSame('', $stored);
            self::assertStringNotContainsString($stored, $body);
        }

        foreach ([$current->tokens, $refreshed->tokens] as $tokens) {
            self::assertStringNotContainsString($tokens->accessToken->reveal(), $body);
            self::assertStringNotContainsString((string) $tokens->refreshToken?->reveal(), $body);
        }

        $narrowed = $this->proofsOf($token, self::idOf($current), '?kinds=first_factor,recovery_code');
        $since    = $this->proofsOf($token, self::idOf($current), '?since=' . $signedInAt->addMinute()->getTimestamp());

        self::assertSame(['first_factor'], array_column((array) $narrowed->json('proofs'), 'kind'));
        self::assertSame(['additional_factor'], array_column((array) $since->json('proofs'), 'kind'));

        $others = $this->proofsOf($token, self::idOf($other))->assertOk();

        self::assertSame(['first_factor'], array_column((array) $others->json('proofs'), 'kind'));

        $others->assertJsonPath('first_factor.kind', 'first_factor');
    }

    /**
     * Time zones other than the application's, and the application's own.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTimeZones(): iterable
    {
        yield from [
            'the application\'s'       => ['UTC'],
            'behind the application'   => ['America/New_York'],
            'ahead of the application' => ['Asia/Tokyo'],
        ];
    }

    /**
     * The time a session's proofs are read from is the same instant in
     * whichever time zone it is given, mutable or not: a step-up made at it is
     * read and one made before it is not, as when it is given in the
     * application's zone.
     *
     * @param  string  $zone
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTimeZones')]
    public function testTheTimeGivenIsTheSameInstantInAnyTimeZone(string $zone): void
    {
        $signedInAt = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($signedInAt);

        $identity = $this->seedIdentity();
        $key      = $this->signIn('api', 'Phone')->record->getKey();
        $at       = $signedInAt->addMinute();

        CarbonImmutable::setTestNow($at);

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($identity, 'api', $key), self::requestClient())->isIssued());

        $since = fn (CarbonInterface $time): array => array_map(
            static fn (RecordedProof $proof): ProofKind => $proof->kind,
            $this->sessions('api')->proofs($key, $time->setTimezone($zone)),
        );

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], $since($signedInAt));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], $since($at->subSecond()));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], $since($at));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], $since(Carbon::instance($at)));
        self::assertSame([], $since($at->addSecond()));
    }

    /**
     * A session of another guard, a revoked one and a pending one answer no
     * proofs and no first factor through the guard, alike, while the pending
     * session's own `proofs()` still reads its first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherGuardsRevokedOrPendingSessionAnswersNothing(): void
    {
        $this->seedIdentity();

        $current = $this->signIn('api', 'Phone');
        $admin   = $this->signIn('admin', 'Console');
        $revoked = $this->signIn('api', 'Revoked');

        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $pending = $this->sessions('api')->signIn('password', self::credentials(), self::requestContext())->pending;

        self::assertNotNull($pending);
        self::assertSame([ProofKind::FIRST_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $pending->proofs()));

        $token = $current->tokens->accessToken->reveal();

        foreach ([self::idOf($admin), self::idOf($revoked), (string) IdentifierCoercion::stringify($pending->id)] as $id) {
            $this->proofsOf($token, $id)->assertOk()->assertExactJson(['proofs' => [], 'first_factor' => null]);
        }
    }

    /**
     * The guard answers the provenance of an active session a provider
     * established, by key and as an instance, and nothing for one no provider
     * established, one of another guard, a revoked one or a pending one, whose
     * provenance stays on its pending session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnswersAnActiveSessionsProvenance(): void
    {
        $this->seedIdentity();

        $current = $this->signIn('api', 'Phone');
        $plain   = $this->signIn('api', 'Plain');
        $admin   = $this->signIn('admin', 'Console');
        $revoked = $this->signIn('api', 'Revoked');

        foreach ([$current, $admin, $revoked] as $session) {
            ProofWriter::provenance($session->record, new Provenance('conn-a', 'tenant-1', linkId: 'link-a'));
        }

        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $pending = $this->sessions('api')->signIn('password', self::credentials(), self::requestContext())->pending;

        self::assertNotNull($pending);

        $sessions = $this->sessions('api');

        foreach ([self::idOf($current), $current->record] as $named) {
            $provenance = $sessions->provenance($named);

            self::assertNotNull($provenance);
            self::assertSame(['conn-a', 'tenant-1', 'link-a'], [$provenance->connectionId, $provenance->tenantId, $provenance->linkId]);
        }

        foreach ([self::idOf($plain), self::idOf($admin), self::idOf($revoked), (string) IdentifierCoercion::stringify($pending->id)] as $id) {
            self::assertNull($sessions->provenance($id));
        }

        self::assertNull($sessions->provenance($admin->record));
    }

    /**
     * A session given as an instance answers only while its key still holds it:
     * the request's own session, as the guard bound it, answers its proofs and
     * first factor over HTTP, and so does its instance; once another sign-in of
     * the same owner reuses its key, the earlier instance answers nothing, with
     * one read of the row, while the key, and the new session's instance,
     * answer the new session's first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnswersASessionGivenAsAnInstanceOnlyWhileItsKeyHoldsIt(): void
    {
        $identity = $this->seedIdentity();
        $current  = $this->signIn('api', 'Phone');
        $key      = $current->record->getKey();

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($identity, 'api', $key), self::requestClient())->isIssued());

        $bound = $this->withHeaders(['Authorization' => 'Bearer ' . $current->tokens->accessToken->reveal()])->getJson('/session/proofs')->assertOk();

        self::assertSame(['additional_factor', 'first_factor'], array_column((array) $bound->json('proofs'), 'kind'));

        $bound->assertJsonPath('first_factor.method', 'password');

        self::assertCount(2, $this->sessions('api')->proofs($current->record));

        Session::query()->whereKey($key)->update(['generation' => (string) Str::uuid7(), 'sign_in_method' => 'passkey']);

        $reused = SessionLookup::find($key);

        self::assertNotNull($reused);

        ProofWriter::clear($reused);
        ProofWriter::record($reused, 'api', SignInProof::unattested('passkey', CarbonImmutable::now())->firstFactor());

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertSame([], $this->sessions('api')->proofs($current->record));
        self::assertNull($this->sessions('api')->firstFactor($current->record));
        self::assertSame(2, $queries);
        self::assertSame('passkey', $this->sessions('api')->firstFactor($key)?->method);
        self::assertSame('passkey', $this->sessions('api')->firstFactor($reused)?->method);
        self::assertSame([ProofKind::FIRST_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $this->sessions('api')->proofs($reused)));
    }

    /**
     * Read inside a transaction, then stepped up and judged again after a
     * factor change in the same transaction, a session is locked only on its
     * own row, each time: the step-up is issued, the session stays active, and
     * the read after them returns the step-up, which commits with the
     * transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReadThenAStepUpAndAFactorChangeOfTheSessionInOneTransaction(): void
    {
        $identity = $this->seedIdentity();
        $record   = $this->signIn('api', 'Phone')->record;
        $key      = $record->getKey();

        self::markSharedLocks();

        $sessions = $this->sessions('api');
        $answers  = [];

        $queries = self::queriesDuring(static function () use ($sessions, $identity, $record, $key, &$answers): void {
            $answers = DB::transaction(static fn (): array => [
                self::kindsOf($sessions->proofs($key)),
                $sessions->stepUp(self::adapterProof($identity, 'api', $key), self::requestClient())->isIssued(),
                $sessions->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $record)->isActive(),
                self::kindsOf($sessions->proofs($key)),
                $sessions->firstFactor($key)?->kind,
            ]);
        });

        $locked = array_values(array_filter($queries, static fn (array $query): bool => self::locksForUpdate($query[0])));

        self::assertSame([[ProofKind::FIRST_FACTOR], true, true, [ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], ProofKind::FIRST_FACTOR], $answers);
        self::assertCount(5, $locked);

        foreach ($locked as [$sql, $bindings]) {
            self::assertMatchesRegularExpression('/^select \* from ["`]authentication_sessions["`] /', $sql);
            self::assertSame([$key], array_values($bindings));
        }

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], self::kindsOf($sessions->proofs($key)));
    }

    /**
     * A limit outside 1 to 200 is refused before anything is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALimitOutsideTheBoundIsRefusedBeforeAnythingIsRead(): void
    {
        $this->seedIdentity();

        $key     = $this->signIn('api', 'Phone')->record->getKey();
        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        try {
            $this->sessions('api')->proofs($key, limit: 201);

            self::fail('A limit of 201 was taken.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A session returns between 1 and 200 proofs at a time.', $exception->getMessage());
        }

        self::assertSame(0, $queries);
    }

    /**
     * The route shows each of the member's memberships the application admits,
     * the one the session acts as among them, and answers `404` for another
     * member's and for one whose tenant was deactivated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testShowsOneOfThePrincipalsTheApplicationAdmits(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $elsewhere = ActivatableTenant::query()->create(['name' => 'Elsewhere', 'is_active' => true]);
        $second    = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $elsewhere->getKey()]);

        [, $foreign] = $this->seedMember('stranger@example.test', $tenant);

        $context = SignInContext::fromRequest(app('request'), principal: $membership);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        $token = $session->tokens->accessToken->reveal();

        $this->principal($token, $membership->getKey())->assertOk()->assertExactJson(['id' => $membership->getKey()]);
        $this->principal($token, $second->getKey())->assertOk()->assertExactJson(['id' => $second->getKey()]);
        $this->principal($token, $foreign->getKey())->assertNotFound();

        $elsewhere->update(['is_active' => false]);

        $this->principal($token, $second->getKey())->assertNotFound();
        $this->principal($token, $membership->getKey())->assertOk();
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
     * The kinds of the proofs, in order.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $proofs
     * @return list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>
     */
    private static function kindsOf(array $proofs): array
    {
        return array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $proofs);
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

    /**
     * Ask the route for one session's proofs and first factor, with the access
     * token and the query given.
     *
     * @param  string  $token
     * @param  string  $id
     * @param  string  $query
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function proofsOf(#[\SensitiveParameter] string $token, string $id, string $query = ''): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/sessions/' . $id . '/proofs' . $query);
    }

    /**
     * Ask the route for one principal, with the access token.
     *
     * @param  string  $token
     * @param  mixed  $id
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function principal(#[\SensitiveParameter] string $token, mixed $id): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/principals/' . IdentifierCoercion::stringify($id));
    }
}
