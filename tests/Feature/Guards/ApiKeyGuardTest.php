<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAdmission;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAuthentication;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineAccount;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\TestCase;

/**
 * Feature tests for the `api_key` guard over HTTP, through the `auth`
 * middleware and the `Auth` facade, against a real database: what a key binds,
 * every reason a key is refused, that a request resolves once, that a key's use
 * is recorded at most once per throttle, and that a machine has no interactive
 * sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyGuard::class)]
#[CoversClass(ApiKeyAuthentication::class)]
#[CoversClass(ApiKeyAdmission::class)]
#[CoversClass(ApiKeyLookup::class)]
#[CoversClass(ApiKeyOutcome::class)]
#[CoversClass(AuthenticationServiceProvider::class)]
final class ApiKeyGuardTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /** @var list<object> Every authentication event dispatched. */
    private array $dispatched = [];

    /**
     * Create the tables, freeze the clock, register the routes and record the
     * events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        foreach (['machine', 'accounts'] as $guard) {
            Route::middleware('auth:' . $guard)->get("/{$guard}/me", static fn (): array => [
                'identity'  => self::keyGuard($guard)->id(),
                'principal' => self::keyGuard($guard)->principal()?->getPrincipalIdentifier(),
                'tenant'    => self::keyGuard($guard)->tenant()?->getTenantIdentifier(),
                'scopes'    => self::keyGuard($guard)->scopes(),
                'device'    => self::keyGuard($guard)->device(),
            ]);
        }

        $events = [Attempting::class, Validated::class, Login::class, Authenticated::class, Failed::class, Logout::class, PrincipalAssigned::class, AuthenticationFailed::class];

        Event::listen($events, function (object $event): void {
            $this->dispatched[] = $event;
        });
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * A request with a live key binds its owner and principal with the key's
     * scopes and no device, as an authentication rather than a sign-in, and
     * records the key's use.
     *
     * @return void
     */
    public function testAKeyAuthenticatesItsOwnerAsItsPrincipalWithItsScopes(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['invoices:read']);

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $issued->key())->assertOk()->assertExactJson([
            'identity'  => $machine->getKey(),
            'principal' => $machine->getKey(),
            'tenant'    => null,
            'scopes'    => ['invoices:read'],
            'device'    => null,
        ]);

        self::assertSame([Authenticated::class, PrincipalAssigned::class], $this->dispatchedClasses());

        $context = $this->dispatchedOf(PrincipalAssigned::class)[0]->context;

        self::assertSame('api_key', $context->method);
        self::assertSame($issued->id, $context->credentialId);
        self::assertSame(['invoices:read'], $context->scopes);
        self::assertSame('machine', $context->guard);
        self::assertSame('2026-04-06 12:00:00', DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));
    }

    /**
     * A key with the longest list of scopes a key may have authenticates with
     * every one of them, in order.
     *
     * @return void
     */
    public function testAKeyWithTheLongestListOfScopesCarriesItWhole(): void
    {
        $machine = $this->seedMachine();
        $scopes  = self::longestScopes();
        $issued  = $this->apiKeys()->issue($machine, $machine, $scopes);

        $this->getWithKey('/machine/me', $issued->key())->assertOk()->assertJsonPath('scopes', $scopes);
    }

    /**
     * A 3D key binds the membership and its tenant.
     *
     * @return void
     */
    public function testAKeyOfAServiceAccountBindsItsMembershipAndTenant(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('accounts')->issue($account, $membership, ['reports']);

        $this->getWithKey('/accounts/me', $issued->key())->assertOk()->assertExactJson([
            'identity'  => $account->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'scopes'    => ['reports'],
            'device'    => null,
        ]);
    }

    /**
     * A 3D key's membership moved to a tenant of another type under the same
     * identifier is `principal_mismatch`: the key recorded the tenant by type
     * as well as identifier, and a replacement rotated meanwhile keeps the
     * recorded type rather than taking the new one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAKeyRefusesATenantOfAnotherTypeUnderTheSameId(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued    = $this->apiKeys('accounts')->issue($account, $membership);
        $workspace = $this->moveToAWorkspaceOfTheSameId($membership, $tenant);

        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), IdentifierCoercion::stringify($workspace->getKey()));

        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_MISMATCH, $issued->id);

        $rotated = $this->apiKeys('accounts')->rotate($membership, $issued->id, 60);

        self::assertNotNull($rotated);

        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $rotated->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_MISMATCH, $rotated->id);

        $membership->forceFill(['tenant_type' => $tenant->getMorphClass()])->save();
        $this->getWithKey('/accounts/me', $issued->key())->assertOk()->assertJsonPath('tenant', $tenant->getKey());
        $this->getWithKey('/accounts/me', $rotated->key())->assertOk()->assertJsonPath('tenant', $tenant->getKey());
    }

    /**
     * A request without a bearer credential attempts nothing and dispatches
     * nothing.
     *
     * @return void
     */
    public function testARequestWithoutAKeyIsAGuestQuietly(): void
    {
        $this->getJson('/machine/me')->assertUnauthorized();
        $this->withHeader('Authorization', 'Bearer ')->getJson('/machine/me')->assertUnauthorized();

        self::assertSame([], $this->dispatched);
    }

    /**
     * Rows of `[key]` that name no key in form: refused before any query.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedKeys(): iterable
    {
        yield from [
            'a jwt'             => ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl'],
            'no secret'         => ['ak_abcdefghijklmnop'],
            'short secret'      => ['ak_abcdefghijklmnop_' . str_repeat('a', 39)],
            'long secret'       => ['ak_abcdefghijklmnop_' . str_repeat('a', 41)],
            'upper public part' => ['ak_ABCDEFGHIJKLMNOP_' . str_repeat('a', 40)],
            'bad prefix'        => ['1k_abcdefghijklmnop_' . str_repeat('a', 40)],
            'symbol in secret'  => ['ak_abcdefghijklmnop_' . str_repeat('a', 39) . '-'],
            'trailing newline'  => ['ak_abcdefghijklmnop_' . str_repeat('a', 40) . "\n"],
        ];
    }

    /**
     * A malformed key is refused as `credential_invalid` without a query.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideMalformedKeys')]
    public function testAMalformedKeyIsRefusedWithoutAQuery(string $key): void
    {
        $queries = $this->countQueries(fn (): bool => Auth::guard('machine')->check(), $key);

        self::assertSame(0, $queries);
        $this->assertRefused(FailureReason::CREDENTIAL_INVALID, null);
    }

    /**
     * An unknown public part and a wrong secret are refused alike, as
     * `credential_invalid`, with one query each; the wrong secret's failure
     * names the key its public part found.
     *
     * @return void
     */
    public function testAnUnknownKeyAndAWrongSecretAreRefusedAlike(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['read']);
        $public  = $issued->summary->publicId;

        $unknown = $this->countQueries(fn (): bool => Auth::guard('machine')->check(), 'ak_zzzzzzzzzzzzzzzz_' . str_repeat('a', 40));

        $this->assertRefused(FailureReason::CREDENTIAL_INVALID, null);

        $wrong = $this->countQueries(fn (): bool => Auth::guard('machine')->check(), $public . '_' . str_repeat('a', 40));

        $this->assertRefused(FailureReason::CREDENTIAL_INVALID, $issued->id);

        self::assertSame(1, $unknown);
        self::assertSame(1, $wrong);
        self::assertSame(['read'], $this->dispatchedOf(AuthenticationFailed::class)[0]->context->scopes);
        self::assertNull(DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));
    }

    /**
     * A key issued for another guard is refused as `credential_guard_mismatch`.
     *
     * @return void
     */
    public function testAnotherGuardsKeyIsRefused(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine);

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();

        $this->assertRefused(FailureReason::CREDENTIAL_GUARD_MISMATCH, $issued->id);
    }

    /**
     * A revoked key is refused at once as `credential_revoked`.
     *
     * @return void
     */
    public function testARevokedKeyIsRefusedAtOnce(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        $this->getWithKey('/machine/me', $issued->key())->assertOk();

        $this->apiKeys()->revoke($machine, $issued->id);

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();

        $this->assertRefused(FailureReason::CREDENTIAL_REVOKED, $issued->id);
    }

    /**
     * A key authenticates until the second before its expiry, and from that
     * second is refused as `credential_expired`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAKeyExpiresFromTheSecondItNames(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, expiresAt: CarbonImmutable::now()->addMinutes(5));

        self::travelMachineClock(299);

        $this->getWithKey('/machine/me', $issued->key())->assertOk();

        self::travelMachineClock(1);

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();

        $this->assertRefused(FailureReason::CREDENTIAL_EXPIRED, $issued->id);
    }

    /**
     * During a rotation's overlap both keys authenticate; once it ends the
     * replaced key is refused as `credential_expired` and its replacement still
     * authenticates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBothKeysWorkDuringARotationsOverlap(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine);
        $rotated  = $this->apiKeys()->rotate($machine, $previous->id, 60);

        self::assertNotNull($rotated);

        $this->getWithKey('/machine/me', $previous->key())->assertOk();
        $this->getWithKey('/machine/me', $rotated->key())->assertOk();

        self::travelMachineClock(60);

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $previous->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::CREDENTIAL_EXPIRED, $previous->id);

        $this->getWithKey('/machine/me', $rotated->key())->assertOk();
    }

    /**
     * A guard whose audience does not allow `api_key` refuses every key as
     * `method_not_allowed`.
     *
     * @return void
     */
    public function testAGuardThatDoesNotAllowApiKeysRefusesThem(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        config()->set('auth.guards.machine.audience.methods', ['password']);

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();

        $this->assertRefused(FailureReason::METHOD_NOT_ALLOWED, $issued->id);
    }

    /**
     * An owner the provider no longer finds is refused as `identity_unknown`,
     * and an inactive one as `identity_inactive`.
     *
     * @return void
     */
    public function testTheOwnerMustBeFoundAndActive(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        $machine->forceFill(['is_active' => false])->save();

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::IDENTITY_INACTIVE, $issued->id);
        self::assertTrue($machine->is($this->dispatchedOf(AuthenticationFailed::class)[0]->context->identity));

        $machine->delete();

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::IDENTITY_UNKNOWN, $issued->id);
    }

    /**
     * A key whose recorded owner type is not the one the provider returns, a
     * key whose owner is a human identity, and a key whose principal is
     * recorded under another type with the same identifier are each refused.
     *
     * @return void
     */
    public function testTheKeysRecordedOwnerAndPrincipalMustBeWhatLoads(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        DB::table('api_keys')->where('id', $issued->id)->update(['authenticatable_type' => MachineAccount::class]);

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::IDENTITY_UNKNOWN, $issued->id);

        DB::table('api_keys')->where('id', $issued->id)->update(['authenticatable_type' => MachineClient::class, 'principal_type' => MachineMembership::class]);

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_MISMATCH, $issued->id);

        $human   = IntegrationIdentity::query()->create(['email' => 'ada@example.test']);
        $humanId = IdentifierCoercion::stringify($human->getKey());

        config()->set('auth.providers.machines.model', IntegrationIdentity::class);
        Auth::forgetGuards();
        DB::table('api_keys')->where('id', $issued->id)->update([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => $humanId,
            'principal_type'       => IntegrationIdentity::class,
            'principal_id'         => $humanId,
        ]);

        $this->dispatched = [];

        $this->getWithKey('/machine/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::CREDENTIAL_INVALID, $issued->id);
    }

    /**
     * A 3D key's membership must still resolve for its account
     * (`principal_mismatch`), be active (`principal_inactive`), act within an
     * active tenant (`tenant_inactive`) and the tenant the key recorded
     * (`principal_mismatch`), and be admitted by the audience
     * (`principal_ineligible`).
     *
     * @return void
     */
    public function testTheMembershipMustStillBeTheKeysAndAdmitted(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('accounts')->issue($account, $membership);

        $membership->forceFill(['type' => 'robot'])->save();
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_INELIGIBLE, $issued->id);

        $other = $tenant->replicate();
        $other->save();
        $membership->forceFill(['tenant_id' => $other->getKey()])->save();
        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_MISMATCH, $issued->id);

        $membership->forceFill(['type' => 'service'])->save();
        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_MISMATCH, $issued->id);

        $membership->forceFill(['tenant_id' => $tenant->getKey()])->save();
        $tenant->forceFill(['is_active' => false])->save();
        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::TENANT_INACTIVE, $issued->id);

        $tenant->forceFill(['is_active' => true])->save();
        $membership->forceFill(['is_active' => false])->save();
        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_INACTIVE, $issued->id);

        $stranger = MachineAccount::query()->create(['name' => 'Stranger']);

        $membership->forceFill(['is_active' => true, 'account_id' => $stranger->getKey()])->save();
        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertUnauthorized();
        $this->assertRefused(FailureReason::PRINCIPAL_MISMATCH, $issued->id);

        $membership->forceFill(['account_id' => $account->getKey()])->save();
        $this->dispatched = [];
        $this->getWithKey('/accounts/me', $issued->key())->assertOk();
    }

    /**
     * The request resolves once: every accessor reads the one result, and a
     * refused key is reported once.
     *
     * @return void
     */
    public function testARequestResolvesOnce(): void
    {
        $this->startMachineRequest('ak_zzzzzzzzzzzzzzzz_' . str_repeat('a', 40));

        $guard = self::keyGuard('machine');

        self::assertFalse($guard->check());
        self::assertNull($guard->user());
        self::assertNull($guard->scopes());
        self::assertCount(1, $this->dispatchedOf(AuthenticationFailed::class));
    }

    /**
     * A key's use is recorded at most once per throttle: not again within it,
     * and again once it has passed; a throttle of 0 records every use. Only
     * that key's use is recorded: another key, never used or stale, is left as
     * it was.
     *
     * @return void
     */
    public function testRecordsAKeysUseAtMostOncePerThrottle(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);
        $unused  = $this->apiKeys()->issue($machine, $machine);
        $stale   = $this->apiKeys()->issue($machine, $machine);

        DB::table('api_keys')->where('id', $stale->id)->update(['last_used_at' => '2026-04-01 12:00:00']);

        $this->getWithKey('/machine/me', $issued->key())->assertOk();

        self::travelMachineClock(59);

        $within = $this->countQueries(fn (): bool => Auth::guard('machine')->check(), $issued->key(), 'update');

        self::assertSame(0, $within);
        self::assertSame('2026-04-06 12:00:00', DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));

        self::travelMachineClock(1);

        $after = $this->countQueries(fn (): bool => Auth::guard('machine')->check(), $issued->key(), 'update');

        self::assertSame(1, $after);
        self::assertSame('2026-04-06 12:01:00', DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));

        config()->set('authentication.api_keys.last_used_throttle_seconds', 0);

        self::assertSame(1, $this->countQueries(fn (): bool => Auth::guard('machine')->check(), $issued->key(), 'update'));
        self::assertNull(DB::table('api_keys')->where('id', $unused->id)->value('last_used_at'));
        self::assertSame('2026-04-01 12:00:00', DB::table('api_keys')->where('id', $stale->id)->value('last_used_at'));
    }

    /**
     * Two requests that both find the last use stale record it once: the
     * second's conditional update matches nothing and leaves its instance as it
     * was.
     *
     * @return void
     */
    public function testAConcurrentUseIsRecordedOnce(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);
        $key     = ApiKeyLookup::find($issued->summary->publicId);
        $stale   = ApiKeyLookup::find($issued->summary->publicId);

        self::assertNotNull($key);
        self::assertNotNull($stale);

        ApiKeyLookup::recordUse($key, CarbonImmutable::now());

        self::assertSame('2026-04-06 12:00:00', $key->last_used_at?->format('Y-m-d H:i:s'));
        self::assertFalse($key->isDirty());

        self::travelMachineClock(30);

        DB::enableQueryLog();

        ApiKeyLookup::recordUse($stale, CarbonImmutable::now());

        self::assertCount(1, DB::getQueryLog());
        self::assertNull($stale->last_used_at);
        self::assertSame('2026-04-06 12:00:00', DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));
    }

    /**
     * A machine has no interactive sign-in: `attempt()` fails without checking
     * anything, reporting `method_not_allowed` for the password method.
     *
     * @return void
     */
    public function testAttemptAlwaysFails(): void
    {
        $this->seedMachine();
        $this->startMachineRequest();

        DB::enableQueryLog();

        self::assertFalse(Auth::guard('machine')->attempt(['email' => 'robot@example.test', 'password' => 'secret']));

        self::assertSame([], DB::getQueryLog());
        self::assertSame([AuthenticationFailed::class], $this->dispatchedClasses());

        $failure = $this->dispatchedOf(AuthenticationFailed::class)[0];

        self::assertSame(AuthenticationFlow::SIGN_IN, $failure->flow);
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $failure->reason);
        self::assertSame('password', $failure->context->method);
        self::assertSame(self::MACHINE_IP, $failure->context->client->ip);
        self::assertFalse(Auth::guard('machine')->check());
    }

    /**
     * `validate()` says whether a key would authenticate, without binding it,
     * recording its use or dispatching anything.
     *
     * @return void
     */
    public function testValidateChecksAKeyQuietly(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);
        $revoked = $this->apiKeys()->issue($machine, $machine);

        $this->apiKeys()->revoke($machine, $revoked->id);

        $this->startMachineRequest();
        $this->dispatched = [];

        $guard = Auth::guard('machine');

        self::assertTrue($guard->validate(['api_key' => $issued->key()]));
        self::assertFalse($guard->validate(['api_key' => $revoked->key()]));
        self::assertFalse($guard->validate(['api_key' => 'nonsense']));
        self::assertFalse($guard->validate(['api_key' => 5]));
        self::assertFalse($guard->validate([]));
        self::assertFalse($guard->hasUser());
        self::assertSame([], $this->dispatched);
        self::assertNull(DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));
    }

    /**
     * Signing out forgets what the key bound for the rest of the request,
     * reporting `Logout`; the key itself stays live.
     *
     * @return void
     */
    public function testLogoutForgetsTheRequestsBinding(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['read']);

        $this->startMachineRequest($issued->key());

        $guard = self::keyGuard('machine');

        self::assertSame(['read'], $guard->scopes());

        $guard->logout();

        self::assertNull($guard->user());
        self::assertNull($guard->scopes());
        self::assertCount(1, $this->dispatchedOf(Logout::class));

        $this->getWithKey('/machine/me', $issued->key())->assertOk();
    }

    /**
     * `Auth::scopes()` reports the key's scopes on the default guard.
     *
     * @return void
     */
    public function testTheFacadeReportsTheKeysScopes(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['a', 'b']);

        $this->startMachineRequest($issued->key());

        Auth::shouldUse('machine');

        self::assertSame(['a', 'b'], Auth::scopes());
        self::assertSame($issued->id, $this->dispatchedOf(PrincipalAssigned::class)[0]->context->credentialId);
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }

    /**
     * Request the path with the key as a bearer credential.
     *
     * @param  string  $path
     * @param  string  $key
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function getWithKey(string $path, #[\SensitiveParameter] string $key): TestResponse
    {
        return $this->withToken($key)->getJson($path);
    }

    /**
     * The named guard, as the API key guard it is.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\ApiKeyGuard
     */
    private static function keyGuard(string $name): ApiKeyGuard
    {
        $guard = Auth::manager()->guard($name);

        self::assertInstanceOf(ApiKeyGuard::class, $guard);

        return $guard;
    }

    /**
     * Count the queries (of the kind, when given) a check makes on a request
     * carrying the key.
     *
     * @param  \Closure(): mixed  $check
     * @param  string  $key
     * @param  ?string  $kind
     * @return int
     */
    private function countQueries(\Closure $check, #[\SensitiveParameter] string $key, ?string $kind = null): int
    {
        $this->startMachineRequest($key);
        $this->dispatched = [];

        $count = 0;

        DB::listen(static function (QueryExecuted $query) use (&$count, $kind): void {
            if ($kind !== null && !str_starts_with(strtolower($query->sql), $kind)) {
                return;
            }

            $count++;
        });

        $check();

        DB::flushQueryLog();

        return $count;
    }

    /**
     * Assert the one event dispatched was the refusal with the reason, on the
     * `api_key` flow, naming the key when one was found.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $credentialId
     * @return void
     */
    private function assertRefused(FailureReason $reason, ?string $credentialId): void
    {
        self::assertSame([AuthenticationFailed::class], $this->dispatchedClasses());

        $failure = $this->dispatchedOf(AuthenticationFailed::class)[0];

        self::assertSame(AuthenticationFlow::API_KEY, $failure->flow);
        self::assertSame($reason, $failure->reason);
        self::assertSame($credentialId, $failure->context->credentialId);
        self::assertSame('api_key', $failure->context->method);
        self::assertNull($failure->identifier);
        self::assertNull($failure->retryAfter);
    }

    /**
     * The classes of the events dispatched, in order.
     *
     * @return list<class-string>
     */
    private function dispatchedClasses(): array
    {
        return array_map(static fn (object $event): string => $event::class, $this->dispatched);
    }

    /**
     * The dispatched events of the class.
     *
     * @template TEvent of object
     *
     * @param  class-string<TEvent>  $class
     * @return list<TEvent>
     */
    private function dispatchedOf(string $class): array
    {
        return array_values(array_filter($this->dispatched, static fn (object $event): bool => $event instanceof $class));
    }
}
