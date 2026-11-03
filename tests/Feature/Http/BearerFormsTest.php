<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\BearerForms;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests, over HTTP through Laravel's `auth` middleware against a real
 * database, of a route that lists both a `jwt` and an `api_key` guard, in
 * either order: a bearer credential in JWT form is the `jwt` guard's alone, so
 * one that fails JWT validation is reported once, as a bearer token, and never
 * looked up as an API key; one in API key form is the `api_key` guard's alone,
 * never parsed as a JWT; a valid credential of either kind authenticates with
 * no failure; revocation is checked on every request; and a route listing one
 * kind reports every credential itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerForms::class)]
#[CoversClass(Authenticate::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(ApiKeyGuard::class)]
final class BearerFormsTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /** @var list<string> The routes listing a person's `jwt` guard and the `api_key` guard, in each order. */
    private const array PERSON_ROUTES = ['/api-then-machine', '/machine-then-api'];

    /** @var list<string> The routes listing the client credentials `jwt` guard and the `api_key` guard, in each order. */
    private const array CLIENT_ROUTES = ['/m2m-then-machine', '/machine-then-m2m'];

    /** @var list<string> SQL of every query run against the API keys table since recording began. */
    private array $keyQueries = [];

    /** @var int Identities seeded so far, numbering their emails. */
    private int $seeded = 0;

    /**
     * Create the tables, freeze the clock, register the routes, and record the
     * events and the queries on the API keys table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $routes = [
            '/api-then-machine' => 'auth:api,machine',
            '/machine-then-api' => 'auth:machine,api',
            '/m2m-then-machine' => 'auth:m2m,machine',
            '/machine-then-m2m' => 'auth:machine,m2m',
            '/api-only'         => 'auth:api',
            '/machine-only'     => 'auth:machine',
            '/api-then-m2m'     => 'auth:api,m2m',
        ];

        foreach ($routes as $path => $middleware) {
            Route::middleware($middleware)->get($path, static fn (): array => ['guard' => Auth::getDefaultDriver(), 'identity' => Auth::id()]);
        }

        $this->recordMachineEvents([AuthenticationFailed::class, Authenticated::class]);

        DB::listen(function (QueryExecuted $query): void {

            if (!str_contains($query->sql, 'api_keys')) {
                return;
            }

            $this->keyQueries[] = $query->sql;
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
     * Rows of `[variant, reason]`: a person's bearer credential in JWT form
     * that fails JWT validation, and the reason the `jwt` guard refuses it
     * with.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideFailingJwts(): iterable
    {
        yield from [
            'bad signature'             => ['signature', FailureReason::TOKEN_INVALID],
            'wrong typ'                 => ['typ', FailureReason::TOKEN_INVALID],
            'expired'                   => ['expired', FailureReason::TOKEN_INVALID],
            'wrong iss'                 => ['iss', FailureReason::TOKEN_INVALID],
            'wrong aud'                 => ['aud', FailureReason::TOKEN_INVALID],
            'another guard'             => ['guard', FailureReason::TOKEN_INVALID],
            'a segment missing'         => ['missing', FailureReason::TOKEN_INVALID],
            'an extra segment'          => ['extra', FailureReason::TOKEN_INVALID],
            'bad base64url'             => ['base64', FailureReason::TOKEN_INVALID],
            'a key with a dot appended' => ['dotted key', FailureReason::TOKEN_INVALID],
        ];
    }

    /**
     * A bearer credential in JWT form that fails JWT validation, on a route
     * listing the person's `jwt` guard and the `api_key` guard in either order,
     * is refused with `401` and reported exactly once, by the `jwt` guard as a
     * bearer token, and is never looked up as an API key: no query touches the
     * API keys table and nothing is reported on the `api_key` flow.
     *
     * @param  string  $variant
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideFailingJwts')]
    public function testAJwtThatFailsIsReportedOnceAndNeverLookedUpAsAKey(string $variant, FailureReason $reason): void
    {
        $token = $this->failingJwt($variant);

        foreach (self::PERSON_ROUTES as $path) {

            $this->bearer($path, $token)->assertUnauthorized();

            $failures = $this->machineEventsOf(AuthenticationFailed::class);

            self::assertCount(1, $failures, $path);
            self::assertSame(AuthenticationFlow::BEARER, $failures[0]->flow);
            self::assertSame($reason, $failures[0]->reason);
            self::assertSame('api', $failures[0]->context->guard);
            self::assertSame([], $this->keyQueries, $path);
        }
    }

    /**
     * A person's valid access token authenticates on the `jwt` guard in either
     * order, with no failure reported and no query on the API keys table.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAValidJwtAuthenticatesWithNoFailureAndNoKeyQuery(): void
    {
        $identity = $this->seedPerson();
        $token    = $this->personToken($identity);

        foreach (self::PERSON_ROUTES as $path) {

            $this->bearer($path, $token)->assertOk()->assertExactJson(['guard' => 'api', 'identity' => $identity->getKey()]);

            self::assertSame([], $this->machineEventsOf(AuthenticationFailed::class), $path);
            self::assertSame([], $this->keyQueries, $path);
        }
    }

    /**
     * A client credentials token is in JWT form too: on a route listing its
     * `jwt` guard and the `api_key` guard it authenticates on the `jwt` guard
     * with no failure, and the only query on the API keys table is the `jwt`
     * guard's hold of the token to its key, by id, never a lookup by the key's
     * public part.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAValidClientCredentialsTokenIsTheJwtGuardsAlone(): void
    {
        [$machine, $issued] = $this->clientKey();

        $token = $this->exchange($issued);

        foreach (self::CLIENT_ROUTES as $path) {

            $this->bearer($path, $token)->assertOk()->assertExactJson(['guard' => 'm2m', 'identity' => $machine->getKey()]);

            self::assertSame([], $this->machineEventsOf(AuthenticationFailed::class), $path);
            self::assertCount(1, $this->keyQueries, $path);
            self::assertStringNotContainsString('public_id', $this->keyQueries[0]);
        }
    }

    /**
     * Rows of `[variant, reason, queries]`: a bearer credential in API key form
     * the `api_key` guard refuses, the reason, and the lookups it costs.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 2: int}>
     */
    public static function provideRefusedKeys(): iterable
    {
        yield from [
            'wrong secret'         => ['secret', FailureReason::CREDENTIAL_INVALID, 1],
            'unknown key'          => ['unknown', FailureReason::CREDENTIAL_INVALID, 1],
            'truncated key'        => ['truncated', FailureReason::CREDENTIAL_INVALID, 0],
            'dotless JWT fragment' => ['fragment', FailureReason::CREDENTIAL_INVALID, 0],
        ];
    }

    /**
     * A bearer credential in API key form that the `api_key` guard refuses, on
     * a route listing a `jwt` guard too in either order, is reported exactly
     * once, on the `api_key` flow, and never parsed as a JWT: nothing is
     * reported as a bearer token.
     *
     * @param  string  $variant
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  int  $queries
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRefusedKeys')]
    public function testAKeyThatIsRefusedIsReportedOnceAndNeverParsedAsAJwt(string $variant, FailureReason $reason, int $queries): void
    {
        $key = $this->refusedKey($variant);

        foreach ([...self::PERSON_ROUTES, ...self::CLIENT_ROUTES] as $path) {

            $this->bearer($path, $key)->assertUnauthorized();

            $failures = $this->machineEventsOf(AuthenticationFailed::class);

            self::assertCount(1, $failures, $path);
            self::assertSame(AuthenticationFlow::API_KEY, $failures[0]->flow);
            self::assertSame($reason, $failures[0]->reason);
            self::assertSame('machine', $failures[0]->context->guard);
            self::assertCount($queries, $this->keyQueries, $path);
        }
    }

    /**
     * A valid key authenticates on the `api_key` guard in either order, with no
     * failure reported.
     *
     * @return void
     */
    public function testAValidKeyAuthenticatesWithNoFailure(): void
    {
        $machine = $this->seedMachine();
        $key     = $this->apiKeys()->issue($machine, $machine)->key()->reveal();

        foreach ([...self::PERSON_ROUTES, ...self::CLIENT_ROUTES] as $path) {

            $this->bearer($path, $key)->assertOk()->assertExactJson(['guard' => 'machine', 'identity' => $machine->getKey()]);

            self::assertSame([], $this->machineEventsOf(AuthenticationFailed::class), $path);
        }
    }

    /**
     * Revocation is checked on every request: a key revoked between two
     * requests is refused on the second as `credential_revoked`, on the
     * `api_key` flow, whichever order the route lists the guards in.
     *
     * @return void
     */
    public function testAKeyRevokedBetweenTwoRequestsIsRefusedOnTheSecond(): void
    {
        foreach (self::PERSON_ROUTES as $path) {

            $machine = $this->seedMachine($path . '@example.test');
            $issued  = $this->apiKeys()->issue($machine, $machine);
            $key     = $issued->key()->reveal();

            $this->bearer($path, $key)->assertOk();

            $this->apiKeys()->revoke($machine, $issued->id);

            $this->bearer($path, $key)->assertUnauthorized();

            $failures = $this->machineEventsOf(AuthenticationFailed::class);

            self::assertCount(1, $failures, $path);
            self::assertSame(AuthenticationFlow::API_KEY, $failures[0]->flow);
            self::assertSame(FailureReason::CREDENTIAL_REVOKED, $failures[0]->reason);
            self::assertSame($issued->id, $failures[0]->context->credentialId);
        }
    }

    /**
     * A client credentials token whose key is revoked is refused on the next
     * request as `credential_revoked`, reported once as a bearer token, and not
     * looked up as an API key, whichever order the route lists the guards in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientCredentialsTokenWhoseKeyIsRevokedIsRefusedOnTheNextRequest(): void
    {
        foreach (self::CLIENT_ROUTES as $path) {

            [$machine, $issued] = $this->clientKey($path . '@example.test');

            $token = $this->exchange($issued);

            $this->bearer($path, $token)->assertOk();

            $this->apiKeys('m2m')->revoke($machine, $issued->id);

            $this->bearer($path, $token)->assertUnauthorized();

            $failures = $this->machineEventsOf(AuthenticationFailed::class);

            self::assertCount(1, $failures, $path);
            self::assertSame(AuthenticationFlow::BEARER, $failures[0]->flow);
            self::assertSame(FailureReason::CREDENTIAL_REVOKED, $failures[0]->reason);
            self::assertSame('m2m', $failures[0]->context->guard);
            self::assertSame($issued->id, $failures[0]->context->credentialId);
            self::assertCount(1, $this->keyQueries, $path);
            self::assertStringNotContainsString('public_id', $this->keyQueries[0]);
        }
    }

    /**
     * A route listing one kind of guard reads every credential itself: a key on
     * a `jwt`-only route is reported as a bearer token, and a JWT on an
     * `api_key`-only route as a malformed key, with no query.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARouteListingOneKindReportsEveryCredential(): void
    {
        $machine = $this->seedMachine();
        $key     = $this->apiKeys()->issue($machine, $machine)->key()->reveal();

        $this->bearer('/api-only', $key)->assertUnauthorized();

        $failures = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failures);
        self::assertSame(AuthenticationFlow::BEARER, $failures[0]->flow);
        self::assertSame(FailureReason::TOKEN_INVALID, $failures[0]->reason);
        self::assertSame([], $this->keyQueries);

        $this->bearer('/machine-only', $this->personToken($this->seedPerson()))->assertUnauthorized();

        $failures = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failures);
        self::assertSame(AuthenticationFlow::API_KEY, $failures[0]->flow);
        self::assertSame(FailureReason::CREDENTIAL_INVALID, $failures[0]->reason);
        self::assertSame([], $this->keyQueries);
    }

    /**
     * A route listing two `jwt` guards gets one report from each guard that
     * refuses the credential, each naming its guard: they are two applications'
     * refusals.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARouteListingTwoJwtGuardsGetsOneReportFromEach(): void
    {
        $this->bearer('/api-then-m2m', $this->failingJwt('signature'))->assertUnauthorized();

        $failures = $this->machineEventsOf(AuthenticationFailed::class);

        $guards = array_map(static fn (AuthenticationFailed $failure): ?string => $failure->context->guard, $failures);
        $flows  = array_map(static fn (AuthenticationFailed $failure): AuthenticationFlow => $failure->flow, $failures);

        self::assertSame(['api', 'm2m'], $guards);
        self::assertSame([AuthenticationFlow::BEARER, AuthenticationFlow::BEARER], $flows);
    }

    /**
     * A guard asked directly, outside the `auth` middleware, reads every
     * credential itself.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAGuardAskedDirectlyReadsEveryCredential(): void
    {
        $this->startMachineRequest($this->personToken($this->seedPerson()));

        $this->machineEvents = [];

        self::assertFalse(Auth::guard('machine')->check());

        $failures = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failures);
        self::assertSame(AuthenticationFlow::API_KEY, $failures[0]->flow);
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
     * A bearer credential in JWT form that fails JWT validation on the `api`
     * guard in the way the variant names.
     *
     * @param  string  $variant
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function failingJwt(string $variant): string
    {
        $token = $this->personToken($this->seedPerson());

        [$header, $payload, $signature] = explode('.', $token);

        return match ($variant) {
            'signature'  => $header . '.' . $payload . '.' . strrev($signature),
            'guard'      => $this->exchange($this->clientKey()[1]),
            'missing'    => $header . '.' . $payload,
            'extra'      => $token . '.' . $signature,
            'base64'     => $header . '.' . $payload . '!.' . $signature,
            'dotted key' => $this->refusedKey('secret') . '.',
            default      => self::resign($token, ...self::resigning($variant)),
        };
    }

    /**
     * A bearer credential in API key form that the `api_key` guard refuses in
     * the way the variant names.
     *
     * @param  string  $variant
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function refusedKey(string $variant): string
    {
        $machine = $this->seedMachine('machine' . ++$this->seeded . '@example.test');
        $issued  = $this->apiKeys()->issue($machine, $machine);

        return match ($variant) {
            'secret'    => $issued->summary->publicId . '_' . str_repeat('a', 40),
            'unknown'   => 'ak_zzzzzzzzzzzzzzzz_' . str_repeat('a', 40),
            'truncated' => substr($issued->key()->reveal(), 0, -1),
            'fragment'  => explode('.', $this->personToken($this->seedPerson()))[0],
            default     => self::fail('Unknown variant ' . $variant),
        };
    }

    /**
     * The header and claims a variant signs the token again with: the wrong
     * `typ`, an expiry an hour past, or the wrong `iss` or `aud`.
     *
     * @param  string  $variant
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    private static function resigning(string $variant): array
    {
        $now = CarbonImmutable::now();

        return match ($variant) {
            'typ'     => [['typ' => 'rt+jwt'], []],
            'expired' => [[], ['iat' => $now->subHours(2)->getTimestamp(), 'exp' => $now->subHour()->getTimestamp()]],
            'iss'     => [[], ['iss' => 'https://elsewhere.example.test']],
            'aud'     => [[], ['aud' => 'https://elsewhere.example.test']],
            default   => self::fail('Unknown variant ' . $variant),
        };
    }

    /**
     * Sign the token's claims again with the guard's key, its header and claims
     * changed as given.
     *
     * @param  string  $token
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private static function resign(string $token, array $header, array $claims): string
    {
        [$encodedHeader, $encodedPayload] = explode('.', $token);

        /** @var array<string, mixed> $head */
        $head = json_decode(JWT::urlsafeB64Decode($encodedHeader), true, flags: JSON_THROW_ON_ERROR);

        /** @var array<string, mixed> $payload */
        $payload = json_decode(JWT::urlsafeB64Decode($encodedPayload), true, flags: JSON_THROW_ON_ERROR);

        $kid = is_string($head['kid'] ?? null) ? $head['kid'] : 'test-kid';

        return JWT::encode([...$payload, ...$claims], config()->string('authentication.jwt.keys.' . $kid), 'HS256', $kid, [...$head, ...$header]);
    }

    /**
     * Persist a person with a unique email.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private function seedPerson(): IntegrationIdentity
    {
        return IntegrationIdentity::query()->create(['email' => 'person' . ++$this->seeded . '@example.test', 'password' => 'unused']);
    }

    /**
     * A valid access token of the `api` guard for the person, with no session.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function personToken(IntegrationIdentity $identity): string
    {
        $this->startMachineRequest();

        $guard = Auth::manager()->guard('api');

        assert($guard instanceof JwtGuard);

        $token = $guard->tokens()->issueAccessToken($identity, $identity, null, null)->reveal();

        Auth::forgetGuards();

        return $token;
    }

    /**
     * A machine and a key of the `m2m` guard.
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\MachineClient, 1: \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey}
     */
    private function clientKey(string $email = 'client@example.test'): array
    {
        $machine = $this->seedMachine($email);

        return [$machine, $this->apiKeys('m2m')->issue($machine, $machine)];
    }

    /**
     * Exchange the key for an access token of the `m2m` guard.
     *
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey  $issued
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function exchange(IssuedApiKey $issued): string
    {
        $this->startMachineRequest();

        $result = Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, substr($issued->key()->reveal(), 20), null);

        self::assertNotNull($result->accessToken);

        Auth::forgetGuards();

        return $result->accessToken->reveal();
    }

    /**
     * Request the path with the bearer credential, recording its events and its
     * queries on the API keys table afresh.
     *
     * @param  string  $path
     * @param  string  $credential
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $path, #[\SensitiveParameter] string $credential): TestResponse
    {
        Auth::forgetGuards();

        $this->machineEvents = [];
        $this->keyQueries    = [];

        return $this->withToken($credential)->getJson($path);
    }
}
