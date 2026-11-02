<?php

declare(strict_types = 1);

namespace Tests\Integration\Routing;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Routing\MeBinding;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithMeBindings;
use Tests\Integration\Fixtures\MeMember;
use Tests\Integration\Fixtures\MeMembership;
use Tests\Integration\Fixtures\MeSession;
use Tests\TestCase;

/**
 * Proves the `me` route binding reads the write connection: an id binds a
 * session and a membership the primary holds and the replica lacks, a scoped
 * child, `me` included, is found through the parent's relationship on the
 * primary, also when the relationship reads while it is built, a session the
 * primary has soft-deleted is a miss though the replica still holds it live,
 * and a refresh credential whose session the primary has revoked binds nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MeBinding::class)]
final class ReplicaMeBindingTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithMeBindings;

    /**
     * Create the tables on the primary and the replica, and register the
     * routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMeTables(self::PRIMARY_CONNECTION);
        $this->createMeTables(self::REPLICA_CONNECTION);

        Route::middleware(['auth:' . self::MEMBERS, SubstituteBindings::class])->group(static function (): void {
            Route::get('/sessions/{session}', static fn (MeSession $session): array => ['id' => $session->getKey()]);
            Route::get('/memberships/{membership}', static fn (MeMembership $membership): array => ['id' => $membership->getKey()]);
            Route::get('/members/{member}/sessions/{session}', static fn (MeMember $member, MeSession $session): array => ['id' => $session->getKey()])->scopeBindings();
            Route::get('/members/{member}/listed/{listedSession}', static fn (MeMember $member, MeSession $listedSession): array => ['id' => $listedSession->getKey()])
                ->scopeBindings();
        });

        Route::middleware(['authentication.refresh:' . self::MEMBERS, SubstituteBindings::class])
            ->post('/refresh/sessions/{session}', static fn (MeSession $session): array => ['id' => $session->getKey()]);
    }

    /**
     * Point the session table back and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMeTables(self::PRIMARY_CONNECTION);

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * What only the primary holds is bound, top-level and as a scoped child.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBindsWhatOnlyThePrimaryHolds(): void
    {
        [$member, [$first, $second]] = $this->seedMember('ada@example.test', 2);

        $current = $this->signedIn('ada@example.test', $first);
        $another = $this->signedIn('ada@example.test', $second);
        $token   = $current->tokens->accessToken->reveal();
        $id      = (string) IdentifierCoercion::stringify($another->record->getKey());

        self::assertFalse(DB::connection(self::REPLICA_CONNECTION)->table(self::SESSIONS)->exists());
        self::assertFalse(DB::connection(self::REPLICA_CONNECTION)->table('me_memberships')->exists());

        $this->bearer('/sessions/' . $id, $token)->assertOk()->assertExactJson(['id' => $id]);
        $this->bearer('/memberships/' . IdentifierCoercion::stringify($second->getKey()), $token)->assertOk()->assertExactJson(['id' => $second->getKey()]);
        $this->bearer('/members/' . IdentifierCoercion::stringify($member->getKey()) . '/sessions/' . $id, $token)->assertOk()->assertExactJson(['id' => $id]);
    }

    /**
     * A session the primary has soft-deleted is a miss, though the replica
     * still holds it live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThePrimaryHasDeletedIsAMiss(): void
    {
        $this->seedMember('ada@example.test');

        $current = $this->signedIn('ada@example.test');
        $deleted = $this->signedIn('ada@example.test');
        $id      = (string) IdentifierCoercion::stringify($deleted->record->getKey());

        $this->copyRowToReplica(self::SESSIONS, $id);

        DB::connection(self::PRIMARY_CONNECTION)->table(self::SESSIONS)->where('id', $id)->update(['deleted_at' => now()]);

        self::assertTrue(DB::connection(self::REPLICA_CONNECTION)->table(self::SESSIONS)->where('id', $id)->whereNull('deleted_at')->exists());

        $this->bearer('/sessions/' . $id, $current->tokens->accessToken->reveal())->assertNotFound();
    }

    /**
     * A `me` child is within the parent's relationship as the primary holds it:
     * the replica holds no session, and a relationship that reads the member's
     * sessions while it is built reads them on the primary too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMeChildIsWithinTheRelationshipThePrimaryHolds(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $token   = $session->tokens->accessToken->reveal();
        $id      = (string) IdentifierCoercion::stringify($session->record->getKey());

        self::assertFalse(DB::connection(self::REPLICA_CONNECTION)->table(self::SESSIONS)->exists());

        $this->bearer('/members/me/sessions/me', $token)->assertOk()->assertExactJson(['id' => $id]);
        $this->bearer('/members/me/listed/me', $token)->assertOk()->assertExactJson(['id' => $id]);
    }

    /**
     * A refresh credential whose session the primary has revoked binds nothing,
     * though the replica still holds the session live: a `401`, reported once
     * as `session_revoked`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCredentialWhoseSessionThePrimaryHasRevokedIsRefused(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $id      = (string) IdentifierCoercion::stringify($session->record->getKey());

        $this->copyRowToReplica('me_members', $member->getKey());
        $this->copyRowToReplica('me_memberships', $membership->getKey());
        $this->copyRowToReplica(self::SESSIONS, $id);

        DB::connection(self::PRIMARY_CONNECTION)->table(self::SESSIONS)->where('id', $id)->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);

        self::assertTrue(DB::connection(self::REPLICA_CONNECTION)->table(self::SESSIONS)->where('id', $id)->whereNull('revoked_at')->exists());

        Event::fake([AuthenticationFailed::class]);
        Auth::forgetGuards();

        $this->postJson('/refresh/sessions/me', ['refresh_token' => $session->tokens->refreshToken?->reveal()])->assertUnauthorized();

        Event::assertDispatchedTimes(AuthenticationFailed::class, 1);
        Event::assertDispatched(
            AuthenticationFailed::class,
            static fn (AuthenticationFailed $event): bool => $event->flow === AuthenticationFlow::REFRESH && $event->reason === FailureReason::SESSION_REVOKED,
        );
    }

    /**
     * Configure the members' guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureMeGuards($config);

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
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
}
