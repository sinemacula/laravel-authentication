<?php

declare(strict_types = 1);

namespace Tests\Feature\ClientCredentials;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult;
use SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests for the OAuth 2.0 client credentials exchange over HTTP: the
 * RFC 6749 request it reads, the token and error responses it answers with,
 * every reason a client is refused, which failures are counted, and the access
 * token it grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientCredentialsExchange::class)]
#[CoversClass(ClientCredentialsRequest::class)]
#[CoversClass(ClientCredentialsResult::class)]
#[CoversClass(PresentedClient::class)]
#[CoversClass(AuthManager::class)]
final class ClientCredentialsExchangeTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /** @var string Media type of a token request's body. */
    private const string FORM = 'application/x-www-form-urlencoded';

    /**
     * Create the tables, freeze the clock, register the token route and record
     * the events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        Route::match(['GET', 'POST'], '/oauth/token', static fn (): ClientCredentialsResult => Auth::clientCredentials('m2m')->fromRequest());
        Route::post('/oauth/accounts/token', static fn (): ClientCredentialsResult => Auth::clientCredentials('m2m_accounts')->fromRequest());

        $this->recordMachineEvents([AuthenticationFailed::class, ClientCredentialsGranted::class]);
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
     * A client authenticated with HTTP Basic gets an access token in RFC 6749's
     * shape, never cached, granting every scope its key grants; the grant is
     * reported with the key and scopes, and the key's use recorded.
     *
     * @return void
     */
    public function testGrantsATokenToAClientAuthenticatedWithBasic(): void
    {
        [$machine, $issued] = $this->machineKey(['invoices:read', 'reports']);

        $response = $this->token('grant_type=client_credentials', $this->basic($issued));

        $response->assertOk()
            ->assertHeader('Pragma', 'no-cache')
            ->assertJsonStructure(['access_token', 'token_type', 'expires_in', 'scope'])
            ->assertJson(['token_type' => 'Bearer', 'expires_in' => 900, 'scope' => 'invoices:read reports']);

        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        $claims = $this->claims($response);

        self::assertSame($issued->id, $claims[Claims::CREDENTIAL_ID->value]);
        self::assertSame('invoices:read reports', $claims[Claims::SCOPE->value]);
        self::assertSame(IdentifierCoercion::stringify($machine->getKey()), $claims[Claims::SUBJECT->value]);
        self::assertNull($claims[Claims::DEVICE_ID->value] ?? null);
        self::assertSame(0, DB::table('devices')->count());

        $granted = $this->machineEventsOf(ClientCredentialsGranted::class);

        self::assertCount(1, $granted);
        self::assertSame($issued->id, $granted[0]->context->credentialId);
        self::assertSame(['invoices:read', 'reports'], $granted[0]->context->scopes);
        self::assertSame('client_credentials', $granted[0]->context->method);
        self::assertSame('m2m', $granted[0]->context->guard);
        self::assertSame('2026-04-06 12:00:00', DB::table('api_keys')->where('id', $issued->id)->value('last_used_at'));
    }

    /**
     * A client authenticated in the body may ask for some of its scopes; the
     * token grants exactly those, in the order asked.
     *
     * @return void
     */
    public function testGrantsTheRequestedScopesToAClientAuthenticatedInTheBody(): void
    {
        [, $issued] = $this->machineKey(['a', 'b', 'c']);

        $this->token($this->body($issued) . '&grant_type=client_credentials&scope=c+a')
            ->assertOk()
            ->assertJson(['scope' => 'c a']);

        self::assertSame(['c', 'a'], $this->machineEventsOf(ClientCredentialsGranted::class)[0]->context->scopes);
    }

    /**
     * The client id and secret in Basic credentials are form-url-decoded, as
     * RFC 6749 section 2.3.1 requires of a client.
     *
     * @return void
     */
    public function testFormUrlDecodesBasicCredentials(): void
    {
        [, $issued] = $this->machineKey();

        $encoded = str_replace('_', '%5F', $issued->summary->publicId) . ':' . substr($issued->key(), 20);

        $this->token('grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($encoded)])->assertOk();
    }

    /**
     * The token lives the guard's access lifetime, and never past its key's
     * expiry.
     *
     * @return void
     */
    public function testATokenNeverOutlivesItsKey(): void
    {
        [, $issued] = $this->machineKey([], CarbonImmutable::now()->addMinutes(3));

        $response = $this->token('grant_type=client_credentials', $this->basic($issued))->assertOk()->assertJson(['expires_in' => 180]);
        $claims   = $this->claims($response);

        self::assertSame(CarbonImmutable::now()->addMinutes(3)->getTimestamp(), $claims[Claims::EXPIRES_AT->value]);
    }

    /**
     * Rows of `[raw body, server, error]`: requests not in RFC 6749's form.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string}>
     */
    public static function provideMalformedRequests(): iterable
    {
        $body = 'client_id=ak_abcdefghijklmnop&client_secret=' . str_repeat('a', 40);

        yield from [
            'no grant type'         => [$body, [], 'invalid_request'],
            'another grant type'    => ["grant_type=password&{$body}", [], 'unsupported_grant_type'],
            'grant type twice'      => ["grant_type=client_credentials&grant_type=client_credentials&{$body}", [], 'invalid_request'],
            'client id twice'       => ["grant_type=client_credentials&{$body}&client_id=ak_abcdefghijklmnop", [], 'invalid_request'],
            'scope as a list'       => ["grant_type=client_credentials&{$body}&scope[]=a", [], 'invalid_request'],
            'json body'             => ["grant_type=client_credentials&{$body}", ['CONTENT_TYPE' => 'application/json'], 'invalid_request'],
            'no client'             => ['grant_type=client_credentials', [], 'invalid_client'],
            'only a client id'      => ['grant_type=client_credentials&client_id=ak_abcdefghijklmnop', [], 'invalid_client'],
            'basic and body'        => ["grant_type=client_credentials&{$body}", ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('a:b')], 'invalid_request'],
            'basic not base64'      => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic not*base64'], 'invalid_client'],
            'basic without a colon' => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('nocolon')], 'invalid_client'],
            'basic empty'           => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic'], 'invalid_client'],
        ];
    }

    /**
     * A request not in form is refused with the RFC 6749 error, reported as
     * invalid credentials, and not counted against any limit; `invalid_client`
     * answers 401, with a Basic challenge when the client tried Basic.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $error
     * @return void
     */
    #[DataProvider('provideMalformedRequests')]
    public function testRefusesARequestNotInForm(string $body, array $server, string $error): void
    {
        $response = $this->token($body, $server);

        $response->assertStatus($error === 'invalid_client' ? 401 : 400)->assertExactJson(['error' => $error]);

        $basic = str_starts_with($server['HTTP_AUTHORIZATION'] ?? '', 'Basic');

        self::assertSame($error === 'invalid_client' && $basic ? 'Basic realm="m2m"' : null, $response->headers->get('WWW-Authenticate'));
        self::assertSame(0, DB::table('rate_limits')->count());

        $failure = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failure);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $failure[0]->reason);
        self::assertSame(AuthenticationFlow::CLIENT_CREDENTIALS, $failure[0]->flow);
        self::assertNull($failure[0]->identifier);
    }

    /**
     * Only a POST is read, and a parameter in the query string is refused even
     * when the body carries it too, so a credential in a URL never works.
     *
     * @return void
     */
    public function testRefusesAGetAndParametersInTheQueryString(): void
    {
        [, $issued] = $this->machineKey();

        $this->call('GET', '/oauth/token?grant_type=client_credentials&' . $this->body($issued))->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);

        foreach (['client_secret=x', 'grant_type=client_credentials', 'scope=a', 'client_id=x'] as $query) {
            $this->token('grant_type=client_credentials&' . $this->body($issued), [], '/oauth/token?' . $query)->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
        }
    }

    /**
     * Rows of `[how the key is broken, the reason]`: every way a presented key
     * fails to authenticate the client.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedClients(): iterable
    {
        yield from [
            'unknown client id' => ['unknown', FailureReason::CREDENTIAL_INVALID],
            'wrong secret'      => ['wrong', FailureReason::CREDENTIAL_INVALID],
            'malformed secret'  => ['malformed', FailureReason::CREDENTIAL_INVALID],
            'revoked'           => ['revoked', FailureReason::CREDENTIAL_REVOKED],
            'expired'           => ['expired', FailureReason::CREDENTIAL_EXPIRED],
            'another guard'     => ['guard', FailureReason::CREDENTIAL_GUARD_MISMATCH],
            'inactive owner'    => ['inactive', FailureReason::IDENTITY_INACTIVE],
            'deleted owner'     => ['deleted', FailureReason::IDENTITY_UNKNOWN],
        ];
    }

    /**
     * Every failure to authenticate the client answers `invalid_client` (401, a
     * Basic challenge for a Basic client), alike, is counted against the client
     * id, and is reported with its own reason and, once a key was found, the
     * key.
     *
     * @param  string  $case
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusedClients')]
    public function testRefusesAClientThatFailsToAuthenticate(string $case, FailureReason $reason): void
    {
        [$machine, $issued] = $this->machineKey(['read'], CarbonImmutable::now()->addMinutes(10));

        [$id, $secret] = [$issued->summary->publicId, substr($issued->key(), 20)];

        match ($case) {
            'unknown'   => $id     = 'ak_zzzzzzzzzzzzzzzz',
            'wrong'     => $secret = str_repeat('a', 40),
            'malformed' => $secret = 'short',
            'revoked'   => $this->apiKeys('m2m')->revoke($machine, $issued->id),
            'expired'   => self::travelMachineClock(600),
            'guard'     => DB::table('api_keys')->update(['guard' => 'machine']),
            'inactive'  => $machine->forceFill(['is_active' => false])->save(),
            default     => $machine->delete(),
        };

        $this->machineEvents = [];

        $response = $this->token('grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode("{$id}:{$secret}")]);

        $response->assertStatus(401)->assertExactJson(['error' => 'invalid_client'])->assertHeader('WWW-Authenticate', 'Basic realm="m2m"');

        $failure = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failure);
        self::assertSame($reason, $failure[0]->reason);
        self::assertSame($id, $failure[0]->identifier);
        self::assertSame(in_array($case, ['unknown', 'malformed'], true) ? null : $issued->id, $failure[0]->context->credentialId);
        self::assertSame(1, DB::table('rate_limits')->count());
        self::assertSame([], $this->machineEventsOf(ClientCredentialsGranted::class));
    }

    /**
     * Rows of `[the client id and secret sent, given the key issued]`: likely
     * client mistakes that put the key's secret where the id belongs.
     *
     * @return iterable<string, array{0: \Closure(string, string): array{0: string, 1: string}}>
     */
    public static function provideMisplacedSecrets(): iterable
    {
        yield from [
            'the whole key as the client id' => [static fn (string $key, string $secret): array => [$key, $secret]],
            'the id and the secret swapped'  => [static fn (string $key, string $secret): array => [$secret, substr($key, 0, 19)]],
        ];
    }

    /**
     * A client id that is not a key's public part in form, such as a whole key
     * or a secret sent in its place, is refused and reported with no
     * identifier, so the secret reaches no event.
     *
     * @param  \Closure(string, string): array{0: string, 1: string}  $sent
     * @return void
     */
    #[DataProvider('provideMisplacedSecrets')]
    public function testASecretSentAsTheClientIdIsNeverReported(\Closure $sent): void
    {
        [, $issued] = $this->machineKey();

        $secret = substr($issued->key(), 20);

        [$id, $other] = $sent($issued->key(), $secret);

        $this->machineEvents = [];

        $this->token('grant_type=client_credentials&client_id=' . $id . '&client_secret=' . $other)->assertStatus(401)->assertExactJson(['error' => 'invalid_client']);

        $failure = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failure);
        self::assertNull($failure[0]->identifier);
        self::assertStringNotContainsString($secret, serialize($failure[0]));
    }

    /**
     * A client authenticated in the body that fails gets no Basic challenge.
     *
     * @return void
     */
    public function testABodyClientGetsNoBasicChallenge(): void
    {
        $this->token('grant_type=client_credentials&client_id=ak_zzzzzzzzzzzzzzzz&client_secret=' . str_repeat('a', 40))
            ->assertStatus(401)
            ->assertHeaderMissing('WWW-Authenticate');
    }

    /**
     * A guard whose audience does not list `client_credentials` refuses every
     * client as `unauthorized_client`, before the key is looked at, and counts
     * nothing.
     *
     * @return void
     */
    public function testAGuardThatDoesNotAllowTheGrantRefusesIt(): void
    {
        [, $issued] = $this->machineKey();

        config()->set('auth.guards.m2m.audience.methods', ['password']);

        $this->token('grant_type=client_credentials', $this->basic($issued))
            ->assertStatus(400)
            ->assertExactJson(['error' => 'unauthorized_client'])
            ->assertHeaderMissing('WWW-Authenticate');

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->machineEventsOf(AuthenticationFailed::class)[0]->reason);
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A principal the guard's audience no longer admits is refused as
     * `unauthorized_client`, and counted.
     *
     * @return void
     */
    public function testAPrincipalTheAudienceDoesNotAdmitIsAnUnauthorizedClient(): void
    {
        [$account, $membership] = $this->seedAccount();

        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership);

        $membership->forceFill(['type' => 'robot'])->save();

        $this->token('grant_type=client_credentials', $this->basic($issued), '/oauth/accounts/token')
            ->assertStatus(400)
            ->assertExactJson(['error' => 'unauthorized_client'])
            ->assertHeaderMissing('WWW-Authenticate');

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->machineEventsOf(AuthenticationFailed::class)[0]->reason);
        self::assertSame(1, DB::table('rate_limits')->count());
    }

    /**
     * Rows of `[what changed since the key was issued, the reason]`: every way
     * the key's principal stops being the one it was issued for.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideUnboundPrincipals(): iterable
    {
        yield from [
            'principal moved tenant' => ['moved', FailureReason::PRINCIPAL_MISMATCH],
            'principal type changed' => ['retyped', FailureReason::PRINCIPAL_MISMATCH],
            'owner type changed'     => ['owner', FailureReason::IDENTITY_UNKNOWN],
            'principal deactivated'  => ['inactive', FailureReason::PRINCIPAL_INACTIVE],
            'tenant deactivated'     => ['tenant', FailureReason::TENANT_INACTIVE],
        ];
    }

    /**
     * A key whose principal moved tenant, whose recorded principal or owner
     * type changed under the same ids, or whose principal or tenant is no
     * longer active authenticates no client: `invalid_client`, counted, with
     * the reason on the event.
     *
     * @param  string  $case
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideUnboundPrincipals')]
    public function testAKeyNoLongerBoundToItsPrincipalAuthenticatesNoClient(string $case, FailureReason $reason): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership, ['read']);
        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        match ($case) {
            'moved'    => $membership->forceFill(['tenant_id' => $other->getKey()])->save(),
            'retyped'  => DB::table('api_keys')->update(['principal_type' => MachineClient::class]),
            'owner'    => DB::table('api_keys')->update(['authenticatable_type' => MachineClient::class]),
            'inactive' => $membership->forceFill(['is_active' => false])->save(),
            default    => $tenant->forceFill(['is_active' => false])->save(),
        };

        $this->token('grant_type=client_credentials', $this->basic($issued), '/oauth/accounts/token')
            ->assertStatus(401)
            ->assertExactJson(['error' => 'invalid_client'])
            ->assertHeader('WWW-Authenticate', 'Basic realm="m2m_accounts"');

        $failure = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failure);
        self::assertSame($reason, $failure[0]->reason);
        self::assertSame($issued->id, $failure[0]->context->credentialId);
        self::assertSame(['read'], $failure[0]->context->scopes);
        self::assertSame(1, DB::table('rate_limits')->count());
    }

    /**
     * Rows of `[scope]` the key does not grant, or that is not a scope string.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidScopes(): iterable
    {
        yield from [
            'not granted'    => ['admin'],
            'partly granted' => ['read admin'],
            'double space'   => ['read  read'],
            'quoted'         => ['"read"'],
        ];
    }

    /**
     * A scope the key does not grant, or one not in form, is `invalid_scope`,
     * reported with the key, and not counted.
     *
     * @param  string  $scope
     * @return void
     */
    #[DataProvider('provideInvalidScopes')]
    public function testRefusesAScopeTheKeyDoesNotGrant(string $scope): void
    {
        [, $issued] = $this->machineKey(['read']);

        $this->token('grant_type=client_credentials&scope=' . rawurlencode($scope), $this->basic($issued))
            ->assertStatus(400)
            ->assertExactJson(['error' => 'invalid_scope'])
            ->assertHeaderMissing('WWW-Authenticate');

        $failure = $this->machineEventsOf(AuthenticationFailed::class)[0];

        self::assertSame(FailureReason::SCOPE_INVALID, $failure->reason);
        self::assertSame($issued->id, $failure->context->credentialId);
        self::assertSame(['read'], $failure->context->scopes);
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A key that grants no scope gets a token whose response has no `scope`
     * member, as RFC 6749 has no empty scope value; the token's own `scope`
     * claim is empty.
     *
     * @return void
     */
    public function testATokenGrantingNoScopeHasNoScopeMember(): void
    {
        [, $issued] = $this->machineKey();

        $response = $this->token('grant_type=client_credentials', $this->basic($issued))->assertOk();

        self::assertSame(['access_token', 'token_type', 'expires_in'], array_keys((array) $response->json()));
        self::assertSame('', $this->claims($response)['scope'] ?? null);
    }

    /**
     * An empty scope asks for every granted scope.
     *
     * @return void
     */
    public function testAnEmptyScopeAsksForEveryGrantedScope(): void
    {
        [, $issued] = $this->machineKey(['read']);

        $this->token('grant_type=client_credentials&scope=', $this->basic($issued))->assertOk()->assertJson(['scope' => 'read']);
    }

    /**
     * A client id is not a secret, so by default failures are not counted
     * against it: wrong secrets sent from one address for a real client id
     * leave the real client, calling from another, its token.
     *
     * @return void
     */
    public function testFailuresForAClientIdDoNotLockTheClientOut(): void
    {
        [, $issued] = $this->machineKey();

        $wrong = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($issued->summary->publicId . ':' . str_repeat('a', 40))];

        for ($attempt = 0; $attempt < 20; $attempt++) {
            $this->token('grant_type=client_credentials', $wrong)->assertStatus(401);
        }

        $this->token('grant_type=client_credentials', ['REMOTE_ADDR' => '203.0.113.9', ...$this->basic($issued)])->assertOk();
    }

    /**
     * Past its limit an address is answered 429 `slow_down` with `Retry-After`,
     * whether or not the client id names a key, without the secret being
     * checked.
     *
     * @return void
     */
    public function testAnAddressPastItsLimitIsToldToSlowDown(): void
    {
        config()->set('authentication.rate_limits.client_credentials.per_ip', ['max' => 3, 'decay_seconds' => 60]);

        [, $issued] = $this->machineKey();

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $this->token('grant_type=client_credentials&client_id=ak_zzzzzzzzzzzzzzzz&client_secret=' . str_repeat('a', 40))->assertStatus(401);
        }

        $this->machineEvents = [];

        $response = $this->token('grant_type=client_credentials', $this->basic($issued));

        $response->assertStatus(429)->assertExactJson(['error' => 'slow_down'])->assertHeader('Retry-After', '60')->assertHeaderMissing('WWW-Authenticate');

        $failure = $this->machineEventsOf(AuthenticationFailed::class)[0];

        self::assertSame(FailureReason::RATE_LIMITED, $failure->reason);
        self::assertSame(60, $failure->retryAfter);
        self::assertNull(DB::table('api_keys')->value('last_used_at'));
    }

    /**
     * A guard that opts in to a limit per client id gets it, from any address:
     * the trade-off the default avoids, since anyone who knows the id can then
     * hold the client back.
     *
     * @return void
     */
    public function testALimitPerClientIdHoldsTheClientBackFromAnyAddress(): void
    {
        config()->set('auth.guards.m2m.rate_limits', ['client_credentials' => ['per_identifier' => ['max' => 3, 'decay_seconds' => 60]]]);

        [, $issued] = $this->machineKey();

        $wrong = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($issued->summary->publicId . ':' . str_repeat('a', 40))];

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $this->token('grant_type=client_credentials', $wrong)->assertStatus(401);
        }

        $this->token('grant_type=client_credentials', ['REMOTE_ADDR' => '203.0.113.9', ...$this->basic($issued)])
            ->assertStatus(429)
            ->assertExactJson(['error' => 'slow_down']);
    }

    /**
     * The exchange may be called directly with a client id and secret, for the
     * client of the guard's request by default or the one given.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testExchangesDirectly(): void
    {
        [, $issued] = $this->machineKey(['read']);

        $this->startMachineRequest();

        $result = Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, substr($issued->key(), 20), 'read', new ClientContext('192.0.2.1', 'Agent'));

        self::assertTrue($result->isGranted());
        self::assertSame(['read'], $result->scopes);
        self::assertSame(900, $result->expiresIn);
        self::assertNull($result->error);
        self::assertSame('192.0.2.1', $this->machineEventsOf(ClientCredentialsGranted::class)[0]->context->client->ip);

        $this->startMachineRequest();

        $refused = Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, str_repeat('a', 40));

        self::assertFalse($refused->isGranted());
        self::assertSame('invalid_client', $refused->error);
        self::assertFalse($refused->toResponse(request())->headers->has('WWW-Authenticate'));
        self::assertSame(FailureReason::CREDENTIAL_INVALID, $refused->reason);
        self::assertSame(self::MACHINE_IP, $this->machineEventsOf(AuthenticationFailed::class)[0]->context->client->ip);
    }

    /**
     * `fromRequest()` reads the request it is given rather than the guard's.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReadsTheRequestItIsGiven(): void
    {
        [, $issued] = $this->machineKey();

        $body = 'grant_type=client_credentials&' . $this->body($issued);

        parse_str($body, $parameters);

        $this->startMachineRequest();

        $request = Request::create('/oauth/token', 'POST', $parameters, [], [], ['CONTENT_TYPE' => self::FORM, 'REMOTE_ADDR' => '192.0.2.9'], $body);
        $result  = Auth::clientCredentials('m2m')->fromRequest($request);

        self::assertTrue($result->isGranted());
        self::assertSame('192.0.2.9', $this->machineEventsOf(ClientCredentialsGranted::class)[0]->context->client->ip);
    }

    /**
     * Only a jwt guard has a client credentials exchange.
     *
     * @return void
     */
    public function testOnlyAJwtGuardHasAnExchange(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [machine] is not a jwt guard, so it has no client credentials exchange.');

        Auth::clientCredentials('machine');
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
     * A machine and a key of the `m2m` guard granting the scopes.
     *
     * @param  list<string>  $scopes
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return array{0: \Tests\Integration\Fixtures\MachineClient, 1: \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey}
     */
    private function machineKey(array $scopes = [], ?CarbonImmutable $expiresAt = null): array
    {
        $machine = $this->seedMachine();

        return [$machine, $this->apiKeys('m2m')->issue($machine, $machine, $scopes, expiresAt: $expiresAt)];
    }

    /**
     * The claims of the access token a response carries.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return array<string, mixed>
     */
    private function claims(TestResponse $response): array
    {
        $token  = $response->json('access_token');
        $claims = is_string($token) ? Auth::manager()->jwt('m2m')->parse($token) : null;

        self::assertNotNull($claims);

        return $claims;
    }

    /**
     * The Basic credentials of the key.
     *
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey  $issued
     * @return array<string, string>
     */
    private function basic(IssuedApiKey $issued): array
    {
        return ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($issued->summary->publicId . ':' . substr($issued->key(), 20))];
    }

    /**
     * The body parameters authenticating with the key.
     *
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey  $issued
     * @return string
     */
    private function body(IssuedApiKey $issued): string
    {
        return 'client_id=' . $issued->summary->publicId . '&client_secret=' . substr($issued->key(), 20);
    }

    /**
     * POST a form-encoded token request, its body parsed as PHP parses a form
     * and kept raw.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $uri
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function token(string $body, array $server = [], string $uri = '/oauth/token'): TestResponse
    {
        parse_str($body, $parameters);

        $this->startMachineRequest();

        return $this->call('POST', $uri, $parameters, [], [], ['CONTENT_TYPE' => self::FORM, 'REMOTE_ADDR' => self::MACHINE_IP, ...$server], $body);
    }
}
