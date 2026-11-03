<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\Stub3dPrincipal;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTenant;

/**
 * EventContext unit tests: the plain values it keeps, the identity, principal,
 * tenant and session named by type and identifier when it is built and never
 * kept as models, and the values as scalars.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
final class EventContextTest extends TestCase
{
    /**
     * Release the clock and the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();
        Relation::requireMorphMap(false);
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * The guard, the client and the method are kept as given, and the identity,
     * principal, tenant and session given only as their types and identifiers.
     *
     * @return void
     */
    public function testKeepsThePlainPartsAndNamesTheModels(): void
    {
        $client  = new ClientContext('203.0.113.7', 'agent');
        $session = new PlainSessionFixture('session-1');

        $context = new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), self::tenant(3), $session, 'password');

        self::assertSame('api', $context->guard);
        self::assertSame($client, $context->client);
        self::assertSame('password', $context->method);
        self::assertSame([PlainIdentityFixture::class, '7'], [$context->identityType, $context->identityId]);
        self::assertSame([PlainPrincipalFixture::class, 'p-1'], [$context->principalType, $context->principalId]);
        self::assertSame([StubTenant::class, '3'], [$context->tenantType, $context->tenantId]);
        self::assertSame('session-1', $context->sessionId);
        self::assertNull($context->credentialId);
        self::assertNull($context->scopes);
    }

    /**
     * The context holds plain values only: no property can hold a model, and
     * every value it holds is a scalar, a list of them, `null`, the time or the
     * client.
     *
     * @return void
     */
    public function testHoldsNoModel(): void
    {
        $context = self::fullContext();
        $types   = [];

        foreach ((new \ReflectionClass($context))->getProperties() as $property) {
            $types[$property->getName()] = (string) $property->getType();
        }

        self::assertSame([
            'occurredAt'       => CarbonImmutable::class,
            'identityType'     => '?string',
            'identityId'       => '?string',
            'principalType'    => '?string',
            'principalId'      => '?string',
            'tenantType'       => '?string',
            'tenantId'         => '?string',
            'sessionId'        => '?string',
            'guard'            => '?string',
            'client'           => ClientContext::class,
            'method'           => '?string',
            'credentialId'     => '?string',
            'scopes'           => '?array',
            'connectionId'     => '?string',
            'requestReference' => '?string',
        ], $types);
    }

    /**
     * The connection and the request reference of a redeemed external result
     * are kept as given, and are `null` by default.
     *
     * @return void
     */
    public function testKeepsTheConnectionAndTheRequestReference(): void
    {
        $client  = new ClientContext(null, null);
        $context = new EventContext('api', $client, new PlainIdentityFixture(7), connectionId: 'connection-7', requestReference: 'request-3');

        self::assertSame(['connection-7', 'request-3'], [$context->connectionId, $context->requestReference]);
        self::assertSame([null, null], [(new EventContext('api', $client))->connectionId, (new EventContext('api', $client))->requestReference]);
    }

    /**
     * The credential's identifier and the scopes it grants are kept as given;
     * `[]` (a credential granting no scope) stays distinct from `null` (no
     * credential limit).
     *
     * @return void
     */
    public function testKeepsTheCredentialAndItsScopes(): void
    {
        $client = new ClientContext(null, null);

        $context = new EventContext('machine', $client, new PlainIdentityFixture(7), credentialId: 'key-1', scopes: ['invoices:read', 'invoices:write']);

        self::assertSame('key-1', $context->credentialId);
        self::assertSame(['invoices:read', 'invoices:write'], $context->scopes);

        $none = new EventContext('machine', $client, credentialId: 'key-2', scopes: []);

        self::assertSame([], $none->scopes);
    }

    /**
     * The context records when it was built, to the microsecond, as the clock
     * says then.
     *
     * @return void
     */
    public function testRecordsWhenItWasBuilt(): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00.123456', 'UTC');

        CarbonImmutable::setTestNow($now);

        $context = new EventContext('api', new ClientContext(null, null));

        CarbonImmutable::setTestNow($now->addHour());

        self::assertTrue($now->equalTo($context->occurredAt));
        self::assertSame('123456', $context->occurredAt->format('u'));
    }

    /**
     * The identifiers are snapshotted as strings, and the identity, principal
     * and tenant by their class as well: the identity's auth identifier, the
     * principal's and the tenant's identifiers, and the session's.
     *
     * @return void
     */
    public function testSnapshotsEveryReferenceAsAString(): void
    {
        $client  = new ClientContext(null, null);
        $context = new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture(42), new PlainTenantFixture(3), new PlainSessionFixture('session-1'));

        self::assertSame(PlainIdentityFixture::class, $context->identityType);
        self::assertSame('7', $context->identityId);
        self::assertSame(PlainPrincipalFixture::class, $context->principalType);
        self::assertSame('42', $context->principalId);
        self::assertSame(PlainTenantFixture::class, $context->tenantType);
        self::assertSame('3', $context->tenantId);
        self::assertSame('session-1', $context->sessionId);
    }

    /**
     * An Eloquent identity, principal or tenant is recorded by its morph class,
     * as a session row records a principal, not by its class name.
     *
     * @return void
     */
    public function testRecordsEloquentModelsByTheirMorphClass(): void
    {
        $principal = new class extends StubPrincipal {
            /**
             * Return the alias the morph map gives the model.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'member';
            }
        };

        $tenant = new class extends StubTenant {
            /**
             * Return the alias the morph map gives the model.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'workspace';
            }
        };

        $principal->forceFill(['id' => 9]);
        $tenant->forceFill(['id' => 4]);

        $context = new EventContext('api', new ClientContext(null, null), $principal, $principal, $tenant);

        self::assertSame('member', $context->identityType);
        self::assertSame('9', $context->identityId);
        self::assertSame('member', $context->principalType);
        self::assertSame('9', $context->principalId);
        self::assertSame('workspace', $context->tenantType);
        self::assertSame('4', $context->tenantId);
    }

    /**
     * Under an enforced morph map, an identity, principal or tenant the map
     * leaves out is recorded by its class name rather than failing the flow the
     * event reports, and one the map names by its alias.
     *
     * @return void
     */
    public function testAModelAnEnforcedMorphMapLeavesOutIsRecordedByItsClassName(): void
    {
        Relation::enforceMorphMap(['member' => StubPrincipal::class]);

        $member = (new StubPrincipal)->forceFill(['id' => 9]);

        $unmapped = new EventContext('api', new ClientContext(null, null), (new StubIdentity)->forceFill(['id' => 7]), new Stub3dPrincipal(['id' => 8]), self::tenant(4));
        $mapped   = new EventContext('api', new ClientContext(null, null), $member, $member);

        self::assertSame(StubIdentity::class, $unmapped->identityType);
        self::assertSame('7', $unmapped->identityId);
        self::assertSame(Stub3dPrincipal::class, $unmapped->principalType);
        self::assertSame('8', $unmapped->principalId);
        self::assertSame(StubTenant::class, $unmapped->tenantType);
        self::assertSame('4', $unmapped->tenantId);
        self::assertSame('member', $mapped->identityType);
        self::assertSame('member', $mapped->principalType);
    }

    /**
     * A context with nothing established keeps only the guard, the client and
     * the time, and every other snapshot is null.
     *
     * @return void
     */
    public function testUnknownPartsAreNull(): void
    {
        $context = new EventContext(null, new ClientContext(null, null));

        self::assertNull($context->guard);
        self::assertNull($context->method);
        self::assertNull($context->identityType);
        self::assertNull($context->identityId);
        self::assertNull($context->principalType);
        self::assertNull($context->principalId);
        self::assertNull($context->tenantType);
        self::assertNull($context->tenantId);
        self::assertNull($context->sessionId);
        self::assertNull($context->connectionId);
        self::assertNull($context->requestReference);
    }

    /**
     * A session id a token named is kept when no session row was loaded.
     *
     * @return void
     */
    public function testKeepsANamedSessionIdWithoutASession(): void
    {
        $context = new EventContext('api', new ClientContext(null, null), sessionId: 'named-session');

        self::assertSame('named-session', $context->sessionId);
    }

    /**
     * A loaded session's own identifier wins over a named one.
     *
     * @return void
     */
    public function testALoadedSessionWinsOverANamedSessionId(): void
    {
        $context = new EventContext('api', new ClientContext(null, null), session: new PlainSessionFixture('loaded'), sessionId: 'named');

        self::assertSame('loaded', $context->sessionId);
    }

    /**
     * The types and identifiers are taken when the context is built: changing
     * the models afterwards changes nothing it holds.
     *
     * @return void
     */
    public function testSnapshotsDoNotFollowLaterChanges(): void
    {
        $principal = self::principal();
        $tenant    = self::tenant(3);

        $principal->forceFill(['id' => 9]);

        $context = new EventContext('api', new ClientContext(null, null), $principal, $principal, $tenant);

        $principal->forceFill(['id' => 10]);
        $tenant->forceFill(['id' => 4]);

        self::assertSame('9', $context->identityId);
        self::assertSame('9', $context->principalId);
        self::assertSame('3', $context->tenantId);
    }

    /**
     * `toArray()` is every value as scalars: the time as an ISO 8601 UTC string
     * to the microsecond whatever the clock's timezone, and the client as its
     * IP address and user agent. It encodes as JSON.
     *
     * @return void
     */
    public function testToArrayIsTheSnapshotAsScalars(): void
    {
        $timezone = date_default_timezone_get();

        date_default_timezone_set('Europe/Paris');

        try {
            CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-04-06 14:00:00.123456'));

            $context = self::fullContext();
        } finally {
            date_default_timezone_set($timezone);
        }

        self::assertInstanceOf(Arrayable::class, $context);
        self::assertSame([
            'occurred_at'       => '2026-04-06T12:00:00.123456Z',
            'guard'             => 'api',
            'method'            => 'password',
            'ip'                => '203.0.113.7',
            'user_agent'        => 'agent',
            'identity_type'     => PlainIdentityFixture::class,
            'identity_id'       => '7',
            'principal_type'    => StubPrincipal::class,
            'principal_id'      => '5',
            'tenant_type'       => PlainTenantFixture::class,
            'tenant_id'         => '3',
            'session_id'        => 'session-1',
            'credential_id'     => 'key-1',
            'scopes'            => ['read'],
            'connection_id'     => 'connection-7',
            'request_reference' => 'request-3',
        ], $context->toArray());
        self::assertSame('14', $context->occurredAt->format('H'));
        self::assertJson(json_encode($context->toArray(), JSON_THROW_ON_ERROR));
    }

    /**
     * Every value survives a round trip unchanged, the time to the microsecond.
     *
     * @return void
     */
    public function testSurvivesASerializeRoundTrip(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-04-06 12:00:00.654321', 'UTC'));

        $client  = new ClientContext('203.0.113.7', 'agent');
        $context = new EventContext(
            'api',
            $client,
            new PlainIdentityFixture(7),
            new PlainPrincipalFixture('p-1'),
            new PlainTenantFixture(3),
            new PlainSessionFixture('loaded'),
            'password',
            credentialId: 'key-1',
            scopes: ['a', 'b'],
        );

        $copy = unserialize(serialize($context));

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertSame($context->toArray(), $copy->toArray());
        self::assertTrue($context->occurredAt->equalTo($copy->occurredAt));
        self::assertEquals($client, $copy->client);
        self::assertEquals($context, $copy);
    }

    /**
     * A context with every part established.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function fullContext(): EventContext
    {
        return new EventContext(
            'api',
            new ClientContext('203.0.113.7', 'agent'),
            new PlainIdentityFixture(7),
            self::principal(),
            new PlainTenantFixture(3),
            new PlainSessionFixture('session-1'),
            'password',
            credentialId: 'key-1',
            scopes: ['read'],
            connectionId: 'connection-7',
            requestReference: 'request-3',
        );
    }

    /**
     * An unsaved tenant model with the given key.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private static function tenant(int $id): StubTenant
    {
        $tenant = new StubTenant;

        $tenant->forceFill(['id' => $id]);

        return $tenant;
    }

    /**
     * An unsaved principal model with key 5 and a `type` attribute, which the
     * context does not record.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private static function principal(): StubPrincipal
    {
        $principal = new StubPrincipal;

        $principal->forceFill(['id' => 5, 'type' => 'staff']);

        return $principal;
    }
}
