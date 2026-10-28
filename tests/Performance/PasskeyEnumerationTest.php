<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Performance\Fixtures\SlowModelProvider;

/**
 * Holds passkey sign-in to the enumeration criteria: usernameless, so there is
 * no identifier to probe, and every refusal that could tell one passkey or
 * account from another (an unknown passkey, another relying party's, one whose
 * owner is gone, a forged signature, another user handle, a regressed counter,
 * a locked account) gives the same result and takes the whole credential
 * timebox, whether or not an owner was looked up, through a provider whose
 * lookup takes a known time when it finds the owner. Sign-in options do no
 * identity work at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeySignIn::class)]
#[CoversClass(PasskeyService::class)]
final class PasskeyEnumerationTest extends PerformanceContractTestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var int The credential timebox, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /**
     * Create the tables, register the slow provider, and seed an identity with
     * a passkey.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        $provider = static fn (Application $app): SlowModelProvider => new SlowModelProvider($app->make(Hasher::class), IntegrationIdentity::class);

        Auth::provider('slow-model', $provider);

        $this->registerPasskey($this->seedIdentity());

        SlowModelProvider::$lookups = 0;
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[looks the owner up, refusal]`: every way a passkey sign-in is
     * refused after its challenge was used, made by the closure.
     *
     * @return iterable<string, array{0: bool, 1: \Closure(self): \SineMacula\Laravel\Authentication\Sessions\SignInResult}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'an unknown passkey'       => [false, static fn (self $test): SignInResult => $test->signInWith(self::stranger())],
            'another relying party\'s' => [false, static fn (self $test): SignInResult => $test->signInFromAnotherRelyingParty()],
            'one whose owner is gone'  => [true, static function (self $test): SignInResult {
                IntegrationIdentity::query()->delete();

                return $test->signInWithPasskey();
            }],
            'a forged signature'              => [true, static fn (self $test): SignInResult => $test->signInWithPasskey(tamper: self::tamper('signature', 'Zm9yZ2Vk'))],
            'another user handle'             => [true, static fn (self $test): SignInResult => $test->signInWithPasskey(tamper: self::tamper('userHandle', 'b3RoZXI'))],
            'a counter that does not advance' => [true, static function (self $test): SignInResult {
                DB::table('passkeys')->update(['sign_count' => 50]);

                return $test->signInWithPasskey();
            }],
            'an account with no attempts' => [true, static function (self $test): SignInResult {
                config()->set('authentication.rate_limits.sign_in.per_identifier', ['max' => 1, 'decay_seconds' => 300]);

                $test->signInWithPasskey(tamper: self::tamper('signature', 'Zm9yZ2Vk'));

                return $test->signInWithPasskey();
            }],
        ];
    }

    /**
     * Each refusal is the same result, `invalid_credentials` with no wait, and
     * takes at least the timebox, whether or not the owner was looked up.
     *
     * @param  bool  $looksUp
     * @param  \Closure(self): \SineMacula\Laravel\Authentication\Sessions\SignInResult  $refusal
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusals')]
    public function testEveryRefusalLooksTheSameAndTakesTheTimebox(bool $looksUp, \Closure $refusal): void
    {
        $this->useTimebox();

        $started = hrtime(true);
        $result  = $refusal($this);
        $took    = hrtime(true) - $started;

        self::assertEquals(SignInResult::failed(FailureReason::INVALID_CREDENTIALS), $result);
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, $took);
        self::assertSame($looksUp, SlowModelProvider::$lookups > 0);
    }

    /**
     * A successful sign-in returns before the timebox, after its owner's slow
     * lookup.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInReturnsBeforeTheTimebox(): void
    {
        $this->useTimebox();

        $started = hrtime(true);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        $took = hrtime(true) - $started;

        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $took);
        self::assertGreaterThanOrEqual(SlowModelProvider::FOUND_MICROSECONDS * 1000, $took);
    }

    /**
     * Sign-in options look no identity up and read no identity table: there is
     * no identifier for them to depend on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInOptionsDoNoIdentityWork(): void
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $this->freshGuard();

        Auth::passkeys('api')->signInOptions();

        self::assertSame(0, SlowModelProvider::$lookups);
        self::assertSame([], array_filter($queries, static fn (string $sql): bool => str_contains($sql, 'integration_identities')));
    }

    /**
     * Configure the guards, over the slow provider, and their relying party.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);

        $config->set('auth.providers.identities', ['driver' => 'slow-model']);
    }

    /**
     * Sign in through `api` with the authenticator's answer to fresh options.
     *
     * @param  \Tests\Fixtures\Passkeys\VirtualAuthenticator  $authenticator
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(VirtualAuthenticator $authenticator): SignInResult
    {
        $options = $this->signInOptions();

        return $this->sessions()->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $authenticator->get($options->options)]);
    }

    /**
     * Sign in through `api` with a passkey registered for another relying
     * party, from an origin both accept.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInFromAnotherRelyingParty(): SignInResult
    {
        config()->set('auth.guards.admin.passkeys', ['id' => 'app.example.test']);

        $this->registerPasskey(IntegrationIdentity::query()->firstOrFail(), 'admin');

        SlowModelProvider::$lookups = 0;

        $options = $this->signInOptions();

        $answer = $this->authenticator()->get(['rpId' => 'app.example.test'] + $options->options);

        return $this->sessions()->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $answer]);
    }

    /**
     * Use the credential timebox for the timing contracts.
     *
     * @return void
     */
    private function useTimebox(): void
    {
        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);
    }

    /**
     * An authenticator holding a passkey registered nowhere.
     *
     * @return \Tests\Fixtures\Passkeys\VirtualAuthenticator
     *
     * @throws \Throwable
     */
    private static function stranger(): VirtualAuthenticator
    {
        $stranger = new VirtualAuthenticator(self::ORIGIN);

        $stranger->create(['rp' => ['id' => self::RP_ID], 'user' => ['id' => VirtualAuthenticator::encode('handle')], 'challenge' => 'challenge']);

        return $stranger;
    }

    /**
     * A change to one member of a credential's response.
     *
     * @param  string  $member
     * @param  string  $value
     * @return \Closure(array<string, mixed>): array<string, mixed>
     */
    private static function tamper(string $member, string $value): \Closure
    {
        return static fn (array $credential): array => ['response' => [$member => $value] + (array) $credential['response']] + $credential;
    }
}
