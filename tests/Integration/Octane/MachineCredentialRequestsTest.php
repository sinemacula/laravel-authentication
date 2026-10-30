<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * End-to-end tests for machine credentials served by one Laravel Octane worker:
 * the `api_key` guard, and the access tokens a client credentials exchange
 * grants on a `jwt` guard. Nothing one request binds (a machine identity, its
 * principal, the scopes its credential grants, a refused credential) is seen by
 * the next, and `Auth::apiKeys()` and `Auth::clientCredentials()` act through
 * the request's sandbox: its request, and the dispatcher bound in it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyGuard::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(ApiKeyService::class)]
#[CoversClass(ClientCredentialsExchange::class)]
#[CoversClass(AuthManager::class)]
final class MachineCredentialRequestsTest extends TestCase
{
    use InteractsWithMachineCredentials, ServesRequestsThroughOctane;

    /** @var string Password of the human identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Freeze the clocks, create the tables, add the routes and boot the worker.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createMachineTables();

        Route::get('/me', static fn (): array => self::contextOf(request()->string('guard')->value()));

        Route::post('/keys', function (): array {
            $keys    = Auth::apiKeys(request()->string('guard')->value());
            $machine = MachineClient::query()->findOrFail(request()->integer('machine'));

            $this->recordInThisRequest([ApiKeyIssued::class]);

            /** @var list<string> $scopes */
            $scopes = request()->array('scopes');

            return ['key' => $keys->issue($machine, $machine, $scopes)->key()];
        });

        Route::post('/oauth/token', function (): array {
            $exchange = Auth::clientCredentials('m2m');

            $this->recordInThisRequest([ClientCredentialsGranted::class]);

            return ['access' => $exchange->fromRequest()->accessToken];
        });

        Route::post('/sign-in', static function (): array {
            $session = Auth::sessions('api')->signIn('password', request()->only('email', 'password'))->session;

            return ['access' => $session?->tokens->accessToken];
        });

        $this->bootOctaneWorker();
    }

    /**
     * Release the clocks and drop the tables.
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
     * One machine's API key, then none, then another machine's: the guest
     * request binds nothing, and the third sees only the second machine and
     * only the scopes its own key grants.
     *
     * @return void
     */
    public function testOneKeyThenNoneThenAnother(): void
    {
        [$robot, $first]  = $this->machineKey('robot@example.test', ['invoices:read']);
        [$other, $second] = $this->machineKey('other@example.test', ['reports']);

        $this->me($first, 'machine')->assertExactJson(['identity' => $robot, 'principal' => $robot, 'device' => null, 'tenant' => null, 'scopes' => ['invoices:read']]);
        $this->me(null, 'machine')->assertExactJson(self::guest());
        $this->me($second, 'machine')->assertExactJson(['identity' => $other, 'principal' => $other, 'device' => null, 'tenant' => null, 'scopes' => ['reports']]);
    }

    /**
     * A key refused for an unknown secret, then a valid key: the refusal is
     * reported once, on its own request, and the valid key authenticates.
     *
     * @return void
     */
    public function testARefusedKeyThenAValidOne(): void
    {
        [$robot, $key] = $this->machineKey('robot@example.test', []);

        $this->recordMachineEvents([AuthenticationFailed::class]);

        $this->me(substr($key, 0, -4) . 'XXXX', 'machine')->assertExactJson(self::guest());
        $this->me($key, 'machine')->assertJson(['identity' => $robot]);

        $failures = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failures);
        self::assertSame(FailureReason::CREDENTIAL_INVALID, $failures[0]->reason);
    }

    /**
     * A client credentials token, which binds a machine with the token's
     * scopes, then no token, then a human's session token, then the machine's
     * token again: the human sees no scopes, and the machine its own again.
     *
     * @return void
     */
    public function testAClientCredentialsTokenThenNoneThenAHumansThenItAgain(): void
    {
        [$robot, $key] = $this->machineKey('robot@example.test', ['invoices:read', 'reports'], 'm2m');

        $machine       = $this->exchange($key, 'reports');
        [$ada, $human] = $this->humanToken();

        $this->me($machine, 'm2m')->assertExactJson([...self::guest(), 'identity' => $robot, 'principal' => $robot, 'scopes' => ['reports']]);
        $this->me(null, 'm2m')->assertExactJson(self::guest());
        $this->me($human, 'api')->assertJson(['identity' => $ada, 'principal' => $ada, 'scopes' => null]);
        $this->me($machine, 'm2m')->assertJson(['identity' => $robot, 'scopes' => ['reports']]);
    }

    /**
     * A token refused by the guard it was not issued for, then that guard's own
     * token: the refusal does not stick.
     *
     * @return void
     */
    public function testATokenOfAnotherGuardThenAValidOne(): void
    {
        [$robot, $key] = $this->machineKey('robot@example.test', ['reports'], 'm2m');

        $machine = $this->exchange($key);

        $this->me($this->humanToken()[1], 'm2m')->assertExactJson(self::guest());
        $this->me($machine, 'm2m')->assertJson(['identity' => $robot]);
    }

    /**
     * `Auth::apiKeys()` and `Auth::clientCredentials()` dispatch through the
     * dispatcher bound in the request they serve, with that request's client,
     * though the guard behind them was resolved before it was bound: each
     * request's events reach its own listeners and no other request's.
     *
     * @return void
     */
    public function testTheServicesReportThroughEachRequestsOwnDispatcher(): void
    {
        $machine = $this->seedMachine()->getKey();

        $issued = $this->serve(self::octaneRequest('POST', '/keys', ['guard' => 'm2m', 'machine' => $machine, 'scopes' => ['reports']], ip: '198.51.100.1'));

        $key = $issued->json('key');

        self::assertIsString($key);

        $granted = $this->serve(self::octaneRequest('POST', '/oauth/token', ['grant_type' => 'client_credentials'], ip: '198.51.100.2', server: self::basic($key)));

        self::assertIsString($granted->json('access'));
        self::assertSame([[['ApiKeyIssued', '198.51.100.1']], [['ClientCredentialsGranted', '198.51.100.2']]], $this->eventsRecordedByEachRequest());
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }

    /**
     * Seed a machine and issue it a key on the guard, through the worker.
     *
     * @param  string  $email
     * @param  list<string>  $scopes
     * @param  string  $guard
     * @return array{0: mixed, 1: string}
     */
    private function machineKey(string $email, array $scopes, string $guard = 'machine'): array
    {
        $machine = $this->seedMachine($email)->getKey();
        $key     = $this->serve(self::octaneRequest('POST', '/keys', ['guard' => $guard, 'machine' => $machine, 'scopes' => $scopes]))->json('key');

        self::assertIsString($key);

        return [$machine, $key];
    }

    /**
     * Exchange the key for an access token of the `m2m` guard, through the
     * worker, asking for the scope given or all the key grants.
     *
     * @param  string  $key
     * @param  ?string  $scope
     * @return string
     */
    private function exchange(string $key, ?string $scope = null): string
    {
        $body   = ['grant_type' => 'client_credentials', ...($scope === null ? [] : ['scope' => $scope])];
        $access = $this->serve(self::octaneRequest('POST', '/oauth/token', $body, server: self::basic($key)))->json('access');

        self::assertIsString($access);

        return $access;
    }

    /**
     * Seed a human identity and sign it in on the `api` guard, through the
     * worker, returning its key and its access token.
     *
     * @return array{0: mixed, 1: string}
     */
    private function humanToken(): array
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = 'ada@example.test';
        $identity->password  = app(Hasher::class)->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        $access = $this->serve(self::octaneRequest('POST', '/sign-in', ['email' => 'ada@example.test', 'password' => self::PASSWORD]))->json('access');

        self::assertIsString($access);

        return [$identity->getKey(), $access];
    }

    /**
     * Ask the guard who is signed in, with the credential or none.
     *
     * @param  ?string  $credential
     * @param  string  $guard
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function me(?string $credential, string $guard): TestResponse
    {
        return $this->serve(self::octaneRequest('GET', '/me', ['guard' => $guard], $credential));
    }

    /**
     * The HTTP Basic credentials of the key (`<prefix>_<public>_<secret>`), as
     * an OAuth client presents them: the public part as the client id, the
     * secret as the client secret.
     *
     * @param  string  $key
     * @return array{HTTP_AUTHORIZATION: string}
     */
    private static function basic(string $key): array
    {
        $separator = strrpos($key, '_');

        self::assertIsInt($separator);

        return ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode(substr($key, 0, $separator) . ':' . substr($key, $separator + 1))];
    }

    /**
     * What a guard reports for a guest.
     *
     * @return array{identity: null, principal: null, device: null, tenant: null, scopes: null}
     */
    private static function guest(): array
    {
        return ['identity' => null, 'principal' => null, 'device' => null, 'tenant' => null, 'scopes' => null];
    }
}
