<?php

declare(strict_types = 1);

namespace Tests\Integration\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyRules;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary;
use SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Scopes\Scopes;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\MachineAccount;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\Integration\Fixtures\NamedIdentity;
use Tests\TestCase;

/**
 * Integration tests for issuing, rotating, revoking and listing API keys
 * through `Auth::apiKeys()`, against a real database on whichever engine the
 * suite runs on: what is stored and shown, the ownership boundary every keyed
 * operation holds to, the bounds a trusted caller is held to, and the events
 * each write reports once committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyService::class)]
#[CoversClass(ApiKeyRules::class)]
#[CoversClass(IssuedApiKey::class)]
#[CoversClass(ApiKeySummary::class)]
#[CoversClass(AuthManager::class)]
final class ApiKeyServiceTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithMachineCredentials;

    /** @var string The identifier of a principal keyed by name. */
    private const string NAMED = 'alice';

    /**
     * Create the tables and freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
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
     * An issued key is shown once in its presented form, and only its public
     * part and the digest of its secret are stored, with the guard, owner,
     * principal, tenant, name, scopes and expiry; `ApiKeyIssued` reports it
     * without the key.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuesAKeyShownOnce(): void
    {
        $machine = $this->seedMachine();

        $this->recordMachineEvents([ApiKeyIssued::class]);

        $issued = $this->apiKeys()->issue($machine, $machine, ['invoices:read', 'invoices:read', 'reports'], 'Billing sync', CarbonImmutable::now()->addDays(30));

        self::assertMatchesRegularExpression('/^ak_[a-z0-9]{16}_[A-Za-z0-9]{40}$/', $issued->key());
        self::assertSame(substr($issued->key(), 0, 19), $issued->summary->publicId);

        $row = DB::table('api_keys')->where('id', $issued->id)->first();

        self::assertNotNull($row);
        self::assertSame($issued->summary->publicId, $row->public_id);
        self::assertSame(hash('sha256', substr($issued->key(), 20)), $row->secret_hash);
        self::assertStringNotContainsString(substr($issued->key(), 20), json_encode($row, JSON_THROW_ON_ERROR));
        self::assertSame('machine', $row->guard);
        self::assertSame('Billing sync', $row->name);
        self::assertSame(MachineClient::class, $row->authenticatable_type);
        self::assertSame(IdentifierCoercion::stringify($machine->getKey()), $row->authenticatable_id);
        self::assertSame(MachineClient::class, $row->principal_type);
        self::assertSame(IdentifierCoercion::stringify($machine->getKey()), $row->principal_id);
        self::assertNull($row->tenant_type);
        self::assertNull($row->tenant_id);
        self::assertSame('["invoices:read","reports"]', $row->scopes);
        self::assertSame('2026-05-06 12:00:00', $row->expires_at);
        self::assertNull($row->last_used_at);
        self::assertNull($row->revoked_at);
        self::assertSame('2026-04-06 12:00:00', $row->created_at);

        self::assertSame(['invoices:read', 'reports'], $issued->summary->scopes);
        self::assertSame('Billing sync', $issued->summary->name);
        self::assertSame('machine', $issued->summary->guard);

        $events = $this->machineEventsOf(ApiKeyIssued::class);

        self::assertCount(1, $events);
        self::assertSame($issued->id, $events[0]->context->credentialId);
        self::assertSame(['invoices:read', 'reports'], $events[0]->context->scopes);
        self::assertSame('machine', $events[0]->context->guard);
        self::assertSame($machine, $events[0]->context->identity);
        self::assertSame(IdentifierCoercion::stringify($machine->getKey()), $events[0]->context->principalId);
        self::assertSame(self::MACHINE_IP, $events[0]->context->client->ip);
        self::assertNull($events[0]->context->method);
        self::assertStringNotContainsString($issued->key(), serialize($events[0]));
    }

    /**
     * Two keys are distinct, and with no name, expiry or scopes a key grants
     * none and never expires.
     *
     * @return void
     */
    public function testKeysAreDistinctAndDefaultToNoScopeAndNoExpiry(): void
    {
        $machine = $this->seedMachine();
        $keys    = $this->apiKeys();

        $first  = $keys->issue($machine, $machine);
        $second = $keys->issue($machine, $machine);

        self::assertNotSame($first->key(), $second->key());
        self::assertNotSame($first->summary->publicId, $second->summary->publicId);
        self::assertSame([], $first->summary->scopes);
        self::assertNull($first->summary->expiresAt);
        self::assertNull($first->summary->name);
    }

    /**
     * A key of a 3D account records the membership it acts as and that
     * membership's tenant.
     *
     * @return void
     */
    public function testRecordsThePrincipalsTenant(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('accounts')->issue($account, $membership);
        $row    = DB::table('api_keys')->where('id', $issued->id)->first();

        self::assertNotNull($row);
        self::assertSame(MachineAccount::class, $row->authenticatable_type);
        self::assertSame(MachineMembership::class, $row->principal_type);
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), $row->principal_id);
        self::assertSame($tenant->getMorphClass(), $row->tenant_type);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->tenant_id);
    }

    /**
     * The configured prefix marks new keys.
     *
     * @return void
     */
    public function testUsesTheConfiguredPrefix(): void
    {
        config()->set('authentication.api_keys.prefix', 'acme2');

        $machine = $this->seedMachine();

        self::assertMatchesRegularExpression('/^acme2_[a-z0-9]{16}_[A-Za-z0-9]{40}$/', $this->apiKeys()->issue($machine, $machine)->key());
    }

    /**
     * A key is only issued for a principal the identity acts as: another
     * identity's principal is refused.
     *
     * @return void
     */
    public function testRefusesAPrincipalTheIdentityDoesNotActAs(): void
    {
        [$account]           = $this->seedAccount();
        [, $otherMembership] = $this->seedAccount();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An API key of guard [accounts] can only be issued for a principal the identity acts as.');

        $this->apiKeys('accounts')->issue($account, $otherMembership);
    }

    /**
     * A key is only issued for a principal the guard's audience admits.
     *
     * @return void
     */
    public function testRefusesAPrincipalTheAudienceDoesNotAdmit(): void
    {
        [$account, $membership] = $this->seedAccount(type: 'robot');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The audience of guard [accounts] does not admit the principal an API key was to be issued for (principal_ineligible).');

        $this->apiKeys('accounts')->issue($account, $membership);
    }

    /**
     * Malformed scopes, and scopes the registry rejects, are refused before
     * anything is stored.
     *
     * @return void
     */
    public function testRefusesScopesThatAreMalformedOrRejected(): void
    {
        $machine = $this->seedMachine();

        try {
            $this->apiKeys()->issue($machine, $machine, ['invoices read']);

            self::fail('Expected a malformed scope to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame(['invoices read'], $exception->scopes);
        }

        $this->app?->instance(ScopeRegistry::class, new class implements ScopeRegistry {
            /**
             * Reject `admin`.
             *
             * @param  string  $guard
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  list<string>  $scopes
             * @return list<string>
             */
            #[\Override]
            public function rejected(string $guard, Principal $principal, array $scopes): array
            {
                return array_values(array_intersect($scopes, ['admin']));
            }
        });

        try {
            $this->apiKeys()->issue($machine, $machine, ['read', 'admin']);

            self::fail('Expected a rejected scope to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame(['admin'], $exception->scopes);
        }

        self::assertSame(0, DB::table('api_keys')->count());
    }

    /**
     * The longest list of scopes a key may have is stored whole on every
     * engine, MySQL's `TEXT` column and its duplicate-ignoring insert included,
     * and read back by the key's summary; one scope more is refused before
     * anything is stored. `ApiKeyGuardTest` and
     * `ClientTokenBearerAuthenticationTest` use a key with that list.
     *
     * @return void
     */
    public function testStoresTheLongestListOfScopesWhole(): void
    {
        $machine = $this->seedMachine();
        $scopes  = self::longestScopes();

        self::assertSame(Scopes::MAX_LIST_LENGTH, strlen(Scopes::format($scopes)));

        $issued = $this->apiKeys()->issue($machine, $machine, $scopes);

        self::assertSame($scopes, $this->apiKeys()->find($machine, $issued->id)?->scopes);
        $stored = DB::table('api_keys')->value('scopes');

        self::assertIsString($stored);
        self::assertSame($scopes, json_decode($stored, true));

        try {
            $this->apiKeys()->issue($machine, $machine, [...$scopes, 'x']);

            self::fail('Expected a list past the bound to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame(['x'], $exception->scopes);
        }

        self::assertSame(1, DB::table('api_keys')->count());
    }

    /**
     * Rows of `[name]` a key may not be given.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidNames(): iterable
    {
        yield from [
            'empty'        => [''],
            'too long'     => [str_repeat('é', 256)],
            'invalid utf8' => ["\xC3\x28"],
            'NUL byte'     => ["prod\0hidden"],
        ];
    }

    /**
     * A name must be 1 to 255 characters of valid UTF-8 without a NUL byte,
     * which PostgreSQL would otherwise store cut short; 255 multibyte
     * characters fit, and a refused name leaves no key and no event behind.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideInvalidNames')]
    public function testRefusesAnInvalidName(string $name): void
    {
        $machine = $this->seedMachine();

        $this->recordMachineEvents([ApiKeyIssued::class]);

        self::assertSame(str_repeat('é', 255), $this->apiKeys()->issue($machine, $machine, name: str_repeat('é', 255))->summary->name);

        try {
            $this->apiKeys()->issue($machine, $machine, name: $name);

            self::fail('Expected the name to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An API key\'s name must be null or 1 to 255 characters of valid UTF-8 without a NUL byte.', $exception->getMessage());
        }

        self::assertSame([str_repeat('é', 255)], DB::table('api_keys')->pluck('name')->all());
        self::assertCount(1, $this->machineEventsOf(ApiKeyIssued::class));
    }

    /**
     * An expiry must be after the current second; it is kept to the whole
     * second.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefusesAnExpiryThatIsNotInTheFuture(): void
    {
        $machine = $this->seedMachine();

        $issued = $this->apiKeys()->issue($machine, $machine, expiresAt: CarbonImmutable::now()->addSeconds(1)->addMilliseconds(500));

        self::assertSame('2026-04-06T12:00:01+00:00', $issued->summary->expiresAt?->toIso8601String());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An API key\'s expiry must be in the future.');

        $this->apiKeys()->issue($machine, $machine, expiresAt: CarbonImmutable::now()->addMilliseconds(900));
    }

    /**
     * A drawn public part that a stored key already has is drawn again, and the
     * key is issued under a fresh one.
     *
     * @return void
     */
    public function testDrawsAgainWhenAPublicPartCollides(): void
    {
        $machine = $this->seedMachine();
        $taken   = $this->apiKeys()->issue($machine, $machine)->summary->publicId;
        $draws   = [$taken, $taken, 'ak_fresh0fresh0fresh'];
        $service = $this->drawingService(static function () use (&$draws): string {
            return (string) array_shift($draws);
        });

        self::assertSame('ak_fresh0fresh0fresh', $service->issue($machine, $machine)->summary->publicId);
        self::assertSame([], $draws);
        self::assertSame(2, DB::table('api_keys')->count());
    }

    /**
     * Public parts that keep colliding give up after three draws, storing
     * nothing more and reporting nothing.
     *
     * @return void
     */
    public function testGivesUpAfterThreeCollidingDraws(): void
    {
        $machine = $this->seedMachine();
        $taken   = $this->apiKeys()->issue($machine, $machine)->summary->publicId;
        $draws   = new \ArrayObject;
        $service = $this->drawingService(static function () use ($taken, $draws): string {
            $draws->append($taken);

            return $taken;
        });

        $this->recordMachineEvents([ApiKeyIssued::class]);

        try {
            $service->issue($machine, $machine);

            self::fail('Expected issuing to give up.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('Could not draw an API key public part that no stored key has in 3 attempts.', $exception->getMessage());
        }

        self::assertCount(3, $draws);
        self::assertSame(1, DB::table('api_keys')->count());
        self::assertSame([], $this->machineEvents);
    }

    /**
     * A rotation whose drawn public part collides is drawn again, and the
     * replacement is issued under a fresh one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotationDrawsAgainWhenAPublicPartCollides(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine);
        $draws    = [$previous->summary->publicId, 'ak_fresh0fresh0fresh'];
        $service  = $this->drawingService(static function () use (&$draws): string {
            return (string) array_shift($draws);
        });

        $rotated = $service->rotate($machine, $previous->id);

        self::assertNotNull($rotated);
        self::assertSame('ak_fresh0fresh0fresh', $rotated->summary->publicId);
        self::assertSame([], $draws);
        self::assertSame($rotated->id, DB::table('api_keys')->where('id', $previous->id)->value('replaced_by'));
        self::assertSame(2, DB::table('api_keys')->count());
    }

    /**
     * A rotation whose public parts keep colliding gives up after three draws,
     * and its transaction takes back the end it set on the replaced key, so
     * that key is neither cut to the overlap nor pointed at a replacement that
     * was never stored, and nothing is reported.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testARotationThatGivesUpChangesNothing(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine);
        $taken    = $previous->summary->publicId;
        $service  = $this->drawingService(static fn (): string => $taken);

        $this->recordMachineEvents([ApiKeyRotated::class]);

        try {
            $service->rotate($machine, $previous->id, 3600);

            self::fail('Expected the rotation to give up.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('Could not draw an API key public part that no stored key has in 3 attempts.', $exception->getMessage());
        }

        $row = DB::table('api_keys')->where('id', $previous->id)->first();

        self::assertNotNull($row);
        self::assertNull($row->rotated_at);
        self::assertNull($row->replaced_by);
        self::assertNull($row->expires_at);
        self::assertSame(1, DB::table('api_keys')->count());
        self::assertSame([], $this->machineEvents);
        self::assertSame($previous->id, $this->apiKeys()->find($machine, $previous->id)?->id);
    }

    /**
     * A key issued inside a transaction on its connection is reported only on
     * commit, and never when the transaction rolls back.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReportsTheIssueOnlyOnceCommitted(): void
    {
        $machine = $this->seedMachine();
        $keys    = $this->apiKeys();

        $this->recordMachineEvents([ApiKeyIssued::class]);

        DB::beginTransaction();

        $keys->issue($machine, $machine);

        self::assertSame([], $this->machineEvents);

        DB::rollBack();

        self::assertSame([], $this->machineEvents);
        self::assertSame(0, DB::table('api_keys')->count());

        DB::transaction(static function () use ($keys, $machine): void {
            $keys->issue($machine, $machine);
        });

        self::assertCount(1, $this->machineEventsOf(ApiKeyIssued::class));
    }

    /**
     * Keys may be issued on a jwt guard, for its client credentials exchange.
     *
     * @return void
     */
    public function testIssuesOnAJwtGuard(): void
    {
        $machine = $this->seedMachine();

        self::assertSame('m2m', $this->apiKeys('m2m')->issue($machine, $machine)->summary->guard);
    }

    /**
     * Only an api_key or jwt guard has API keys.
     *
     * @return void
     */
    public function testAGuardOfAnotherDriverHasNoApiKeys(): void
    {
        config()->set('auth.guards.web', ['driver' => 'session', 'provider' => 'machines']);

        Auth::shouldUse('machine');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is neither an api_key nor a jwt guard, so it has no API keys.');

        Auth::apiKeys('web');
    }

    /**
     * Without a name, the default guard's keys are used, and its name is the
     * one reported.
     *
     * @return void
     */
    public function testUsesTheDefaultGuard(): void
    {
        config()->set('auth.guards.web', ['driver' => 'session', 'provider' => 'machines']);

        Auth::shouldUse('machine');

        $machine = $this->seedMachine();

        self::assertSame('machine', Auth::apiKeys()->issue($machine, $machine)->summary->guard);

        Auth::shouldUse('web');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is neither an api_key nor a jwt guard, so it has no API keys.');

        Auth::apiKeys();
    }

    /**
     * Revoking marks the principal's key revoked, once: only the call that
     * revoked it reports it, with the owner, principal, key and scopes.
     *
     * @return void
     */
    public function testRevokesOnce(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['read']);

        $this->recordMachineEvents([ApiKeyRevoked::class]);

        self::travelMachineClock(60);

        self::assertTrue($this->apiKeys()->revoke($machine, $issued->id));
        self::assertFalse($this->apiKeys()->revoke($machine, $issued->id));

        self::assertSame('2026-04-06 12:01:00', DB::table('api_keys')->where('id', $issued->id)->value('revoked_at'));
        self::assertSame('2026-04-06 12:01:00', DB::table('api_keys')->where('id', $issued->id)->value('updated_at'));

        $events = $this->machineEventsOf(ApiKeyRevoked::class);

        self::assertCount(1, $events);
        self::assertSame($issued->id, $events[0]->context->credentialId);
        self::assertSame(['read'], $events[0]->context->scopes);
        self::assertTrue($machine->is($events[0]->context->identity));
        self::assertSame($machine, $events[0]->context->principal);
        self::assertSame('2026-04-06T12:01:00+00:00', $this->apiKeys()->find($machine, $issued->id)?->revokedAt?->toIso8601String());
    }

    /**
     * Rows of `[key id]` that name no key of the principal: malformed, unknown.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideKeyIdsOfNoKey(): iterable
    {
        yield from [
            'not a uuid' => ['not-a-uuid'],
            'unknown'    => ['0195f4a2-7b1c-7000-8000-000000000001'],
        ];
    }

    /**
     * A key id that names no key is absent to every keyed operation.
     *
     * @param  string  $keyId
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideKeyIdsOfNoKey')]
    public function testAKeyIdThatNamesNoKeyIsAbsent(string $keyId): void
    {
        $machine = $this->seedMachine();

        $this->apiKeys()->issue($machine, $machine);

        self::assertNull($this->apiKeys()->find($machine, $keyId));
        self::assertFalse($this->apiKeys()->revoke($machine, $keyId));
        self::assertNull($this->apiKeys()->rotate($machine, $keyId));
    }

    /**
     * A key of another principal, of a principal of another type that shares
     * its id, or of another guard, is absent to every keyed operation and is
     * left as it was.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnotherPrincipalsOrGuardsKeyIsAbsent(): void
    {
        $owner    = $this->seedMachine();
        $stranger = $this->seedMachine('stranger@example.test');
        $issued   = $this->apiKeys()->issue($owner, $owner);

        self::assertNull($this->apiKeys()->find($stranger, $issued->id));
        self::assertFalse($this->apiKeys()->revoke($stranger, $issued->id));
        self::assertNull($this->apiKeys()->rotate($stranger, $issued->id));
        self::assertSame([], $this->apiKeys()->keys($stranger));

        [, $namesake] = $this->seedAccount();

        self::assertSame($owner->getKey(), $namesake->getKey());
        self::assertNull($this->apiKeys()->find($namesake, $issued->id));
        self::assertFalse($this->apiKeys()->revoke($namesake, $issued->id));
        self::assertNull($this->apiKeys()->rotate($namesake, $issued->id));
        self::assertSame([], $this->apiKeys()->keys($namesake));

        self::assertNull($this->apiKeys('m2m')->find($owner, $issued->id));
        self::assertFalse($this->apiKeys('m2m')->revoke($owner, $issued->id));
        self::assertNull($this->apiKeys('m2m')->rotate($owner, $issued->id));
        self::assertSame([], $this->apiKeys('m2m')->keys($owner));

        $row = DB::table('api_keys')->where('id', $issued->id)->first();

        self::assertNotNull($row);
        self::assertNull($row->revoked_at);
        self::assertNull($row->rotated_at);
        self::assertSame(1, DB::table('api_keys')->count());
    }

    /**
     * A principal with no identifier names no key, and costs no query.
     *
     * @return void
     */
    public function testAnUnsavedPrincipalHasNoKeys(): void
    {
        $unsaved = new MachineClient;
        $keys    = $this->apiKeys();

        DB::enableQueryLog();

        self::assertSame([], $keys->keys($unsaved));
        self::assertNull($keys->find($unsaved, '0195f4a2-7b1c-7000-8000-000000000001'));
        self::assertSame([], DB::getQueryLog());
    }

    /**
     * The principal's keys are listed newest first, revoked ones included,
     * without any secret.
     *
     * @return void
     */
    public function testListsThePrincipalsKeysNewestFirst(): void
    {
        $machine = $this->seedMachine();
        $first   = $this->apiKeys()->issue($machine, $machine, name: 'first');

        self::travelMachineClock(10);

        $second = $this->apiKeys()->issue($machine, $machine, name: 'second');

        $this->apiKeys()->revoke($machine, $first->id);

        $listed = $this->apiKeys()->keys($machine);

        self::assertSame([$second->id, $first->id], array_map(static fn (ApiKeySummary $summary): string => $summary->id, $listed));
        self::assertNotNull($listed[1]->revokedAt);
        $shown = json_encode(array_map(static fn (ApiKeySummary $summary): array => $summary->toArray(), $listed), JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString(substr($second->key(), 20), $shown);
    }

    /**
     * Rotating a key that never expires issues its replacement with the same
     * guard, owner, principal, tenant, name and scopes, ends the replaced key
     * at the overlap's end, records the rotation on it, and reports it with the
     * replaced key's id.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotatesAKeyThatNeverExpires(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $previous = $this->apiKeys('accounts')->issue($account, $membership, ['read'], 'sync');

        $this->recordMachineEvents([ApiKeyRotated::class]);

        self::travelMachineClock(30);

        $rotated = $this->apiKeys('accounts')->rotate($membership, $previous->id, 3600);

        self::assertNotNull($rotated);
        self::assertNotSame($previous->key(), $rotated->key());
        self::assertSame(['read'], $rotated->summary->scopes);
        self::assertSame('sync', $rotated->summary->name);
        self::assertNull($rotated->summary->expiresAt);

        $old = DB::table('api_keys')->where('id', $previous->id)->first();
        $new = DB::table('api_keys')->where('id', $rotated->id)->first();

        self::assertNotNull($old);
        self::assertNotNull($new);
        self::assertSame('2026-04-06 13:00:30', $old->expires_at);
        self::assertSame('2026-04-06 12:00:30', $old->rotated_at);
        self::assertSame($rotated->id, $old->replaced_by);
        self::assertSame('2026-04-06 12:00:30', $old->updated_at);
        self::assertSame($tenant->getMorphClass(), $new->tenant_type);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $new->tenant_id);
        self::assertSame($old->authenticatable_id, $new->authenticatable_id);
        self::assertSame($old->principal_type, $new->principal_type);
        self::assertNull($new->rotated_at);

        $events = $this->machineEventsOf(ApiKeyRotated::class);

        self::assertCount(1, $events);
        self::assertSame($previous->id, $events[0]->previousKeyId);
        self::assertSame($rotated->id, $events[0]->context->credentialId);
        self::assertSame(['read'], $events[0]->context->scopes);
        self::assertSame($membership, $events[0]->context->principal);
        self::assertTrue($account->is($events[0]->context->identity));
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $events[0]->context->tenantId);
    }

    /**
     * An overlap of 0 ends a key that never expires at once.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotatesWithNoOverlap(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine);

        $rotated = $this->apiKeys()->rotate($machine, $previous->id, 0, CarbonImmutable::now()->addDays(90));

        self::assertNotNull($rotated);
        self::assertSame('2026-04-06 12:00:00', DB::table('api_keys')->where('id', $previous->id)->value('expires_at'));
        self::assertSame('2026-07-05T12:00:00+00:00', $this->apiKeys()->find($machine, $rotated->id)?->expiresAt?->toIso8601String());
    }

    /**
     * A key that expires before the overlap ends keeps its own expiry; one that
     * expires after it is cut to the overlap's end. The replacement does not
     * inherit the replaced key's expiry: given none, it never expires.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotationNeverExtendsAKeysExpiry(): void
    {
        $machine = $this->seedMachine();
        $soon    = $this->apiKeys()->issue($machine, $machine, expiresAt: CarbonImmutable::now()->addMinutes(10));
        $later   = $this->apiKeys()->issue($machine, $machine, expiresAt: CarbonImmutable::now()->addDays(10));

        $this->apiKeys()->rotate($machine, $soon->id, 3600);

        $replacement = $this->apiKeys()->rotate($machine, $later->id, 3600);

        self::assertSame('2026-04-06 12:10:00', DB::table('api_keys')->where('id', $soon->id)->value('expires_at'));
        self::assertSame('2026-04-06 13:00:00', DB::table('api_keys')->where('id', $later->id)->value('expires_at'));
        self::assertNull($replacement?->summary->expiresAt);
    }

    /**
     * Without an overlap, the configured default applies; an overlap outside 0
     * to the configured maximum is refused before anything changes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testHoldsTheOverlapToItsBounds(): void
    {
        config()->set('authentication.api_keys.rotation_overlap_seconds', '120');
        config()->set('authentication.api_keys.max_rotation_overlap_seconds', 600);

        $machine = $this->seedMachine();
        $first   = $this->apiKeys()->issue($machine, $machine);

        $this->apiKeys()->rotate($machine, $first->id);

        self::assertSame('2026-04-06 12:02:00', DB::table('api_keys')->where('id', $first->id)->value('expires_at'));

        $second = $this->apiKeys()->issue($machine, $machine);

        self::assertNotNull($this->apiKeys()->rotate($machine, $second->id, 600));

        $third = $this->apiKeys()->issue($machine, $machine);

        foreach ([601, -1] as $overlap) {
            try {
                $this->apiKeys()->rotate($machine, $third->id, $overlap);

                self::fail("Expected an overlap of {$overlap} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith('An API key\'s rotation overlap must be from 0 to 600 seconds', $exception->getMessage());
            }
        }

        self::assertNull(DB::table('api_keys')->where('id', $third->id)->value('rotated_at'));
    }

    /**
     * Only a live, unrotated key rotates: a revoked, expired or already rotated
     * key gives `null` and nothing changes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotatesOnlyALiveUnrotatedKey(): void
    {
        $machine = $this->seedMachine();
        $keys    = $this->apiKeys();
        $revoked = $keys->issue($machine, $machine);
        $expired = $keys->issue($machine, $machine, expiresAt: CarbonImmutable::now()->addSeconds(5));
        $rotated = $keys->issue($machine, $machine);

        $keys->revoke($machine, $revoked->id);

        self::assertNotNull($keys->rotate($machine, $rotated->id));

        self::travelMachineClock(5);

        $this->recordMachineEvents([ApiKeyRotated::class]);

        self::assertNull($this->apiKeys()->rotate($machine, $revoked->id));
        self::assertNull($this->apiKeys()->rotate($machine, $expired->id));
        self::assertNull($this->apiKeys()->rotate($machine, $rotated->id));
        self::assertSame([], $this->machineEvents);
        self::assertSame(4, DB::table('api_keys')->count());
    }

    /**
     * A rotation's scopes are held to the registry again: a scope it no longer
     * allows refuses the rotation and leaves the key as it was.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRotationHoldsTheScopesToTheRegistryAgain(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine, ['admin']);

        $this->app?->instance(ScopeRegistry::class, new class implements ScopeRegistry {
            /**
             * Reject `admin`.
             *
             * @param  string  $guard
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  list<string>  $scopes
             * @return list<string>
             */
            #[\Override]
            public function rejected(string $guard, Principal $principal, array $scopes): array
            {
                return array_values(array_intersect($scopes, ['admin']));
            }
        });

        try {
            $this->apiKeys()->rotate($machine, $previous->id);

            self::fail('Expected the rotation to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame(['admin'], $exception->scopes);
        }

        self::assertNull(DB::table('api_keys')->where('id', $previous->id)->value('rotated_at'));
        self::assertSame(1, DB::table('api_keys')->count());
    }

    /**
     * An already rotated key, still inside its overlap, does not rotate again,
     * and its scopes are not held to the registry again for it: the answer is
     * `null`, not a refused scope.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testARotatedKeyInsideItsOverlapDoesNotRotateAgain(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine, ['admin']);

        self::assertNotNull($this->apiKeys()->rotate($machine, $previous->id, 600));

        $this->app?->instance(ScopeRegistry::class, new class implements ScopeRegistry {
            /**
             * Reject every scope.
             *
             * @param  string  $guard
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  list<string>  $scopes
             * @return list<string>
             */
            #[\Override]
            public function rejected(string $guard, Principal $principal, array $scopes): array
            {
                return $scopes;
            }
        });

        self::assertNull($this->apiKeys()->rotate($machine, $previous->id, 600));
        self::assertSame(2, DB::table('api_keys')->count());
    }

    /**
     * A key revoked after the rotation read it, but before the rotation's
     * conditional update, is not rotated: the update matches nothing, nothing
     * is inserted and nothing is reported.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAKeyRevokedDuringTheRotationIsNotRotated(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine);

        $this->app?->instance(ScopeRegistry::class, new class ($previous->id) implements ScopeRegistry {
            /**
             * Constructor.
             *
             * @param  string  $keyId
             */
            public function __construct(

                /** The key to revoke while the rotation asks about its scopes. */
                private readonly string $keyId,
            ) {}

            /**
             * Revoke the key, as a concurrent request would, and reject
             * nothing.
             *
             * @param  string  $guard
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  list<string>  $scopes
             * @return list<string>
             */
            #[\Override]
            public function rejected(string $guard, Principal $principal, array $scopes): array
            {
                DB::table('api_keys')->where('id', $this->keyId)->update(['revoked_at' => '2026-04-06 12:00:00']);

                return [];
            }
        });

        $this->recordMachineEvents([ApiKeyRotated::class]);

        self::assertNull($this->apiKeys()->rotate($machine, $previous->id));
        self::assertSame([], $this->machineEvents);
        self::assertSame(1, DB::table('api_keys')->count());
        self::assertNull(DB::table('api_keys')->where('id', $previous->id)->value('rotated_at'));
    }

    /**
     * A key is not issued for a membership whose tenant cannot be loaded, so a
     * key never records a tenant other than the one its principal acts
     * within; once the tenant is gone, revoking an existing key reports no
     * tenant.
     *
     * @return void
     */
    public function testATenantThatCannotBeLoaded(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('accounts')->issue($account, $membership);

        $tenant->delete();

        $this->recordMachineEvents([ApiKeyRevoked::class]);

        self::assertTrue($this->apiKeys('accounts')->revoke($membership, $issued->id));
        self::assertNull($this->machineEventsOf(ApiKeyRevoked::class)[0]->context->tenant);

        $this->expectException(TenantUnavailableException::class);

        $this->apiKeys('accounts')->issue($account, $membership->fresh() ?? $membership);
    }

    /**
     * A rotation inside a transaction that rolls back leaves the key as it was
     * and reports nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARolledBackRotationChangesNothing(): void
    {
        $machine  = $this->seedMachine();
        $previous = $this->apiKeys()->issue($machine, $machine);
        $keys     = $this->apiKeys();

        $this->recordMachineEvents([ApiKeyRotated::class]);

        DB::beginTransaction();

        self::assertNotNull($keys->rotate($machine, $previous->id));
        self::assertSame([], $this->machineEvents);

        DB::rollBack();

        self::assertSame([], $this->machineEvents);
        self::assertNull(DB::table('api_keys')->where('id', $previous->id)->value('rotated_at'));
        self::assertSame(1, DB::table('api_keys')->count());
    }

    /**
     * The owner reported for a revocation is the identity the key records, and
     * none once the guard's provider no longer finds it.
     *
     * @return void
     */
    public function testReportsNoOwnerOnceItIsGone(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        MachineClient::query()->whereKey($machine->getKey())->delete();

        $this->recordMachineEvents([ApiKeyRevoked::class]);

        self::assertTrue($this->apiKeys()->revoke($machine, $issued->id));
        self::assertNull($this->machineEventsOf(ApiKeyRevoked::class)[0]->context->identity);
    }

    /**
     * With the principal columns under a collation that counts distinct
     * identifiers as equal, a principal whose identifier differs from the key's
     * only in case or accent finds, lists, revokes and rotates none of its
     * keys, which are left as they were with nothing reported, while the exact
     * principal still finds and lists the key, and rotates it.
     *
     * @param  string  $folded
     * @return void
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherIdentifierTheCollationCountsAsEqualHasNoKeys(string $folded): void
    {
        self::foldColumns('api_keys', ['principal_type', 'principal_id']);

        $id = $this->issueKeyRecording(NamedIdentity::class, self::NAMED);

        self::assertColumnFolds('api_keys', 'principal_id', $folded);

        $this->assertAbsentTo(self::namedIdentity($folded), $id);

        $owner = self::namedIdentity(self::NAMED);

        self::assertSame($id, $this->apiKeys()->find($owner, $id)?->id);
        self::assertSame([$id], array_map(static fn (ApiKeySummary $summary): string => $summary->id, $this->apiKeys()->keys($owner)));
        self::assertNotNull($this->apiKeys()->rotate($owner, $id));
    }

    /**
     * With the principal columns under a collation that counts distinct types
     * as equal, a principal whose type differs from the key's only in case
     * finds, lists, revokes and rotates none of its keys, which are left as
     * they were with nothing reported.
     *
     * @return void
     */
    public function testAnotherTypeTheCollationCountsAsEqualHasNoKeys(): void
    {
        self::foldColumns('api_keys', ['principal_type', 'principal_id']);

        $id = $this->issueKeyRecording(strtolower(NamedIdentity::class), self::NAMED);

        self::assertColumnFolds('api_keys', 'principal_type', NamedIdentity::class);

        $this->assertAbsentTo(self::namedIdentity(self::NAMED), $id);
    }

    /**
     * With the principal columns under a collation that counts distinct
     * identifiers as equal, the exact principal revokes its key once one whose
     * identifier differs only in case or accent could not.
     *
     * @param  string  $folded
     * @return void
     */
    #[DataProvider('provideFoldedKeys')]
    public function testTheExactPrincipalStillRevokesItsKey(string $folded): void
    {
        self::foldColumns('api_keys', ['principal_type', 'principal_id']);

        $id = $this->issueKeyRecording(NamedIdentity::class, self::NAMED);

        self::assertColumnFolds('api_keys', 'principal_id', $folded);
        self::assertFalse($this->apiKeys()->revoke(self::namedIdentity($folded), $id));
        self::assertTrue($this->apiKeys()->revoke(self::namedIdentity(self::NAMED), $id));
        self::assertNotNull(DB::table('api_keys')->where('id', $id)->value('revoked_at'));
    }

    /**
     * With the guard column under a collation that counts distinct guards as
     * equal, a guard whose name differs from the key's only in case finds,
     * lists, revokes and rotates none of its keys, which are left as they were
     * with nothing reported, while the key's own guard still finds, lists and
     * revokes it.
     *
     * @return void
     */
    public function testAnotherGuardTheCollationCountsAsEqualHasNoKeys(): void
    {
        self::foldColumns('api_keys', ['guard']);

        config()->set('auth.guards.MACHINE', config('auth.guards.machine'));

        $machine = $this->seedMachine();
        $id      = $this->apiKeys()->issue($machine, $machine)->id;

        self::assertColumnFolds('api_keys', 'guard', 'MACHINE');

        $this->assertAbsentTo($machine, $id, 'MACHINE');

        self::assertSame($id, $this->apiKeys()->find($machine, $id)?->id);
        self::assertSame([$id], array_map(static fn (ApiKeySummary $summary): string => $summary->id, $this->apiKeys()->keys($machine)));
        self::assertTrue($this->apiKeys()->revoke($machine, $id));
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
     * The `machine` guard's key service, drawing public parts with the
     * generator.
     *
     * @param  \Closure(string): string  $draw
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService
     */
    private function drawingService(\Closure $draw): ApiKeyService
    {
        $guard = Auth::manager()->guard('machine');

        self::assertInstanceOf(ApiKeyGuard::class, $guard);
        self::assertNotNull($this->app);

        return new ApiKeyService($guard, $this->app, $draw);
    }

    /**
     * Issue a key to a machine and record it as held for the principal with the
     * type and identifier, as an application whose principals are keyed by name
     * would hold it, and return its id.
     *
     * @param  string  $type
     * @param  string  $id
     * @return string
     */
    private function issueKeyRecording(string $type, string $id): string
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        DB::table('api_keys')->where('id', $issued->id)->update(['principal_type' => $type, 'principal_id' => $id]);

        return $issued->id;
    }

    /**
     * Assert the principal finds, lists, revokes and rotates none of the keys
     * through the guard, that the key is left as it was, and that nothing is
     * reported.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $id
     * @param  string  $guard
     * @return void
     */
    private function assertAbsentTo(Principal $principal, string $id, string $guard = 'machine'): void
    {
        $this->recordMachineEvents([ApiKeyRevoked::class, ApiKeyRotated::class]);

        self::assertNull($this->apiKeys($guard)->find($principal, $id));
        self::assertSame([], $this->apiKeys($guard)->keys($principal));
        self::assertFalse($this->apiKeys($guard)->revoke($principal, $id));
        self::assertNull($this->apiKeys($guard)->rotate($principal, $id));

        $row = DB::table('api_keys')->where('id', $id)->first();

        self::assertNotNull($row);
        self::assertNull($row->revoked_at);
        self::assertNull($row->rotated_at);
        self::assertNull($row->expires_at);
        self::assertSame(1, DB::table('api_keys')->count());
        self::assertSame([], $this->machineEvents);
    }
}
