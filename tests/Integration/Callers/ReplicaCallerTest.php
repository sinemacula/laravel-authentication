<?php

declare(strict_types = 1);

namespace Tests\Integration\Callers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithCallers;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;

/**
 * Proves the caller of a request is read, and its principals admitted, on the
 * write connection: a membership the primary holds and the replica lacks is the
 * caller's, one the primary has soft-deleted is not though the replica still
 * holds it live, and a refresh credential whose session the primary has revoked
 * has no caller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Caller::class)]
#[CoversClass(CallerCredentials::class)]
final class ReplicaCallerTest extends TestCase
{
    use InteractsWithCallers, InteractsWithLaggingReplica;

    /**
     * Create the tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createCallerTables(self::PRIMARY_CONNECTION);
        $this->createCallerTables(self::REPLICA_CONNECTION);
    }

    /**
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * Another membership of the caller's member is the caller's as the primary
     * holds it: one the replica lacks is admitted, and one the primary has
     * soft-deleted is not, though the replica still holds it live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalIsAdmittedAsThePrimaryHoldsIt(): void
    {
        [, [$first, $second, $deleted]] = $this->seedMember('ada@example.test', 3);

        $session = $this->signedIn('ada@example.test', $first);

        $this->copyRowToReplica('caller_memberships', $deleted->getKey());

        DB::connection(self::PRIMARY_CONNECTION)->table('caller_memberships')->where('id', $deleted->getKey())->update(['deleted_at' => now()]);

        self::assertFalse(DB::connection(self::REPLICA_CONNECTION)->table('caller_memberships')->where('id', $second->getKey())->exists());
        self::assertTrue(DB::connection(self::REPLICA_CONNECTION)->table('caller_memberships')->where('id', $deleted->getKey())->whereNull('deleted_at')->exists());

        $this->serve(Request::create('/caller', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]));

        $caller = Auth::caller();

        self::assertNotNull($caller);
        self::assertTrue($caller->owns($second));
        self::assertFalse($caller->owns($deleted));
    }

    /**
     * A refresh credential whose session the primary has revoked has no caller,
     * though the replica still holds the session live: it is reported once as
     * `session_revoked`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCredentialWhoseSessionThePrimaryHasRevokedHasNoCaller(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $id      = (string) IdentifierCoercion::stringify($session->record->getKey());

        $this->copyRowToReplica('caller_members', $member->getKey());
        $this->copyRowToReplica('caller_memberships', $membership->getKey());
        $this->copyRowToReplica('authentication_sessions', $id);

        DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->where('id', $id)->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);

        self::assertTrue(DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->where('id', $id)->whereNull('revoked_at')->exists());

        $request = Request::create('/refresh/sessions/current', 'POST', ['refresh_token' => $session->tokens->refreshToken?->reveal()]);

        DeclaredCredential::refresh(self::MEMBERS)->declareOn($request);

        Event::fake([AuthenticationFailed::class]);

        $this->serve($request);

        self::assertNull(Auth::caller());

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

        self::configureCallerGuards($config);

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
     * Serve the request, on guards resolved afresh.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    private function serve(Request $request): void
    {
        app()->instance('request', $request);

        Auth::forgetGuards();
    }
}
