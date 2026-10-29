<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\ResetRequests;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Integration tests of a password reset for identities on the default
 * connection while the devices, and so the codes, live on a connection of their
 * own: the proof, the password and the revocation cannot be one transaction, so
 * a request and a reset are refused as a misconfiguration before anything is
 * counted when the provider's configuration names its model, and a reset once
 * its proof is accepted for the identity found when it does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(ResetRequests::class)]
#[CoversClass(SharedConnection::class)]
final class SeparateConnectionResetSubmissionsTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string The refusal every reset here throws. */
    private const string REFUSAL = 'A password reset spends its proof with its change to the identity in one transaction, so '
        . SeparateConnectionCutoffIdentity::class . ' must be on the device model\'s connection: the identity is on [testing], the devices on [device_store].';

    /**
     * Create the identity table on the default connection and the device, code
     * and limit tables on the device connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        self::createDeviceTable('devices', 'id', SeparateConnectionDevice::CONNECTION);

        self::createCodeTableOn(SeparateConnectionDevice::CONNECTION);

        SeparateConnectionCutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => app(Hasher::class)->make('the old passphrase')]);

        FakePasswordResetLinkSender::fake($this->app);

        Auth::provider('unnamed-model', static fn (Application $app): ModelProvider => new ModelProvider($app->make(Hasher::class), SeparateConnectionCutoffIdentity::class));
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

        parent::tearDown();
    }

    /**
     * With the provider's model named in its configuration, a request for a
     * link and a reset are both refused before anything is counted or issued:
     * no link goes out that could never reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestAndAResetAreRefusedBeforeAnythingIsCounted(): void
    {
        $attempts = [
            'request' => static fn (): mixed => Auth::passwords('api')->sendResetLink(['email' => 'ada@example.test']),
            'reset'   => static fn (): mixed => Auth::passwords('api')->reset(['email' => 'ada@example.test', 'token' => str_repeat('a', 43), 'password' => 'a passphrase']),
        ];

        foreach ($attempts as $name => $attempt) {
            try {
                $attempt();
                self::fail("A {$name} spanning two connections was attempted.");
            } catch (\LogicException $exception) {
                self::assertSame(self::REFUSAL, $exception->getMessage(), $name);
            }
        }

        self::assertSame(0, DB::table('rate_limits')->count());
        self::assertSame(0, DB::connection(SeparateConnectionDevice::CONNECTION)->table('one_time_codes')->count());
    }

    /**
     * A provider whose configuration names no model has the identity it finds
     * checked only once a proof is accepted: without one, a known identifier
     * and an unknown one both answer `invalid`, so the refusal says nothing to
     * someone guessing; with one, the reset is refused and the proof stays
     * unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProviderWithoutANamedModelIsRefusedOnlyWithAValidProof(): void
    {
        config()->set('auth.providers.identities', ['driver' => 'unnamed-model']);

        foreach (['ada@example.test', 'nobody@example.test'] as $email) {
            $result = Auth::passwords('api')->reset(['email' => $email, 'token' => str_repeat('a', 43), 'password' => 'a brand new passphrase']);

            self::assertSame(ResetStatus::INVALID, $result->status, $email);
        }

        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('api', 'email', 'ada@example.test'), CarbonImmutable::now(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        try {
            Auth::passwords('api')->reset(['email' => 'ada@example.test', 'token' => $issued->code, 'password' => 'a brand new passphrase']);
            self::fail('A reset spanning two connections was made.');
        } catch (\LogicException $exception) {
            self::assertSame(self::REFUSAL, $exception->getMessage());
        }

        self::assertNull(DB::connection(SeparateConnectionDevice::CONNECTION)->table('one_time_codes')->value('consumed_at'));
    }

    /**
     * Keep the devices and codes on their own connection and configure the
     * `api` guard.
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

        $config->set('database.connections.' . SeparateConnectionDevice::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.device.model', SeparateConnectionDevice::class);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionCutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }
}
