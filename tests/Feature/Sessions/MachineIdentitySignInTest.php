<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionPreconditions;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\ProvenIdentitySignIn;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests holding non-human identities to having no password, no
 * interactive sign-in, no session and no refresh, at every entry point that
 * verifies something: a password is never checked for a machine, every sign-in
 * method's identity is refused at admission (a passkey whose owner became a
 * machine included), a machine's device can neither refresh nor switch
 * principal, a session token naming one is refused, and the token service
 * issues it no session token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInAdmission::class)]
#[CoversClass(PasswordSignIn::class)]
#[CoversClass(PasskeySignIn::class)]
#[CoversClass(SessionPreconditions::class)]
#[CoversClass(RefreshAdmission::class)]
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(JwtTokenService::class)]
final class MachineIdentitySignInTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var string Email the machine and the human share, so a lookup by it finds either. */
    private const string EMAIL = 'robot@example.test';

    /**
     * Create the tables, register a method that proves its input, and record
     * the failures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Schema::create('machine_clients', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        app(SignInMethodManager::class)->extend('proven', fn (): SignInMethod => new ProvenIdentitySignIn);

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);

        $this->recordEvents([AuthenticationFailed::class]);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('machine_clients');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A machine's password is never checked, whatever it stores: signing in
     * with it fails as invalid credentials, as `attempt()` and `validate()` do,
     * without asking the hasher and without counting the machine's account.
     *
     * @return void
     */
    public function testAMachineHasNoPassword(): void
    {
        $this->seedMachineWithPassword();

        $hasher = \Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('check');

        $this->app?->instance('hash', $hasher);

        $result = $this->sessions('machines')->signIn('password', self::credentials(self::EMAIL));

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $result->reason);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, DB::table('devices')->count());

        $this->recordEvents([AuthenticationFailed::class]);

        $guard = $this->freshGuard('machines');

        self::assertFalse($guard->attempt(self::credentials(self::EMAIL)));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertFalse($guard->validate(self::credentials(self::EMAIL)));
        self::assertFalse($guard->check());
    }

    /**
     * A wrong password for a human account counts that account, and the same
     * attempt for a machine counts nothing more than the identifier and the IP
     * address: a machine has no account whose password can be guessed.
     *
     * @return void
     */
    public function testAMachinesAccountIsNeverCounted(): void
    {
        $this->seedMachineWithPassword();
        $this->seedIdentity('human@example.test');

        $this->sessions('machines')->signIn('password', ['email' => self::EMAIL, 'password' => 'wrong']);

        $forMachine = DB::table('rate_limits')->count();

        DB::table('rate_limits')->delete();

        $this->sessions('api')->signIn('password', ['email' => 'human@example.test', 'password' => 'wrong']);

        self::assertSame(2, $forMachine);
        self::assertSame(3, DB::table('rate_limits')->count());
    }

    /**
     * Rows of `[method]`: sign-in methods a machine's identity may be proven
     * through, each of which admission refuses alike.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideProvenMethods(): iterable
    {
        yield 'a method that proved its input' => ['proven'];
    }

    /**
     * Whatever method proved it, a machine is refused at admission as
     * `machine_identity`: no session, no device, no pending sign-in.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideProvenMethods')]
    public function testAnySignInOfAMachineIsRefused(string $method): void
    {
        $machine = $this->seedMachineWithPassword();

        $result = $this->sessions('machines')->signIn($method, ['email' => self::EMAIL]);

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::MACHINE_IDENTITY, $result->reason);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $failure->reason);
        self::assertSame(AuthenticationFlow::SIGN_IN, $failure->flow);
        self::assertTrue($machine->is($failure->context->identity));
        self::assertSame(0, DB::table('devices')->count());
        self::assertSame(0, DB::table('pending_sign_ins')->count());
    }

    /**
     * A passkey a person registered, whose owner is now a machine with the same
     * key, signs nothing in: the assertion verifies, and admission refuses the
     * machine as `machine_identity` with no device. A machine cannot register a
     * passkey of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyWhoseOwnerBecameAMachineIsRefused(): void
    {
        $human = $this->seedIdentity(self::EMAIL);

        $this->registerPasskey($human);

        $machine = $this->seedMachineWithPassword();

        self::assertSame($human->getKey(), $machine->getKey());

        DB::table('passkeys')->update(['authenticatable_type' => MachineClient::class]);

        config()->set('auth.providers.identities.model', MachineClient::class);

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->signInWithPasskey();

        self::assertSame(FailureReason::MACHINE_IDENTITY, $result->reason);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FailureReason::MACHINE_IDENTITY, AuthenticationFlow::SIGN_IN, PasskeySignIn::NAME], [$failure->reason, $failure->flow, $failure->context->method]);
        self::assertTrue($machine->is($failure->context->identity));
        self::assertSame(0, DB::table('devices')->count());
    }

    /**
     * A session started for an externally verified machine is refused the same
     * way, before anything is resolved or written.
     *
     * @return void
     */
    public function testStartingASessionForAMachineIsRefused(): void
    {
        $machine = $this->seedMachineWithPassword();

        $result = $this->sessions('machines')->start($machine, null, 'proven');

        self::assertSame(FailureReason::MACHINE_IDENTITY, $result->reason);
        self::assertSame(0, DB::table('devices')->count());
    }

    /**
     * A device a machine owns (left from before it became one, say) neither
     * refreshes nor switches principal, and its access token is refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAMachinesDeviceNeitherRefreshesNorSwitchesNorAuthenticates(): void
    {
        $session = $this->humanSessionHandedToAMachine();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame(FailureReason::MACHINE_IDENTITY, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(AuthenticationFlow::REFRESH, $this->recordedEvent(AuthenticationFailed::class)->flow);

        $this->recordEvents([AuthenticationFailed::class]);

        $switched = $this->sessions()->switchPrincipal($session->tokens->refreshToken, $session->principal);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $switched->reason);

        $this->recordEvents([AuthenticationFailed::class]);
        Auth::forgetGuards();

        $this->withToken($session->tokens->accessToken)->getJson('/me')->assertUnauthorized();

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $failure->reason);
        self::assertSame(AuthenticationFlow::BEARER, $failure->flow);
        self::assertInstanceOf(MachineClient::class, $failure->context->identity);
        self::assertNull(DB::table('devices')->value('revoked_at'));
    }

    /**
     * The token service issues a machine no session token: no access token for
     * it, and no refresh token for a device it owns or for it as the principal.
     *
     * @return void
     */
    public function testTheTokenServiceIssuesAMachineNoSessionToken(): void
    {
        $this->humanSessionHandedToAMachine();

        $machine = MachineClient::query()->sole();
        $tokens  = Auth::manager()->jwt('api');
        $owned   = Device::query()->sole();
        $unowned = (new Device)->forceFill([
            'id'                  => 'unowned',
            'idle_expires_at'     => CarbonImmutable::now()->addDay(),
            'absolute_expires_at' => CarbonImmutable::now()->addDay(),
        ]);

        $issues = [
            'an access token'                  => static fn (): string => $tokens->issueAccessToken($machine, $machine, null),
            'a refresh token for its device'   => static fn (): string => $tokens->issueRefreshToken($owned, 'rotation-id'),
            'a refresh token as its principal' => static fn (): string => $tokens->issueRefreshToken($unowned, 'rotation-id', $machine),
        ];

        foreach ($issues as $name => $issue) {
            try {
                $issue();

                self::fail("Expected the token service to refuse {$name}.");
            } catch (\LogicException $exception) {
                self::assertSame('A non-human identity has no session: it gets access tokens only from a client credentials exchange.', $exception->getMessage(), $name);
            }
        }

        self::assertNotSame('', $tokens->issueRefreshToken($unowned, 'rotation-id'));
    }

    /**
     * Configure the guards: `api` over humans, and `machines`, a jwt guard over
     * machine clients that allows every method.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);

        $config->set('auth.guards.api.audience.methods', ['password', 'proven', 'passkey']);
        $config->set('auth.providers.machines', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'machines', 'audience' => ['methods' => ['password', 'proven']]]);
    }

    /**
     * Persist a machine whose stored password would match.
     *
     * @return \Tests\Integration\Fixtures\MachineClient
     */
    private function seedMachineWithPassword(): MachineClient
    {
        return MachineClient::query()->create(['email' => self::EMAIL, 'password' => app(Hasher::class)->make(self::PASSWORD)]);
    }

    /**
     * Sign a human in on `api`, then make the device's owner and principal a
     * machine with the same key, and point the guard's provider at machines:
     * the state a device is in when its owner became a machine.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private function humanSessionHandedToAMachine(): SignedInSession
    {
        $human   = $this->seedIdentity(self::EMAIL);
        $machine = $this->seedMachineWithPassword();

        self::assertSame($human->getKey(), $machine->getKey());

        $session = $this->sessions()->signIn('password', self::credentials(self::EMAIL))->session;

        self::assertNotNull($session);

        DB::table('devices')->update(['authenticatable_type' => MachineClient::class, 'principal_type' => MachineClient::class]);

        config()->set('auth.providers.identities.model', MachineClient::class);

        $guard = $this->freshGuard();

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $session;
    }
}
