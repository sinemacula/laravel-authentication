<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\PasswordChanges;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;

/**
 * Integration tests of setting a password for an identity on the default
 * connection whose sessions live on a connection of their own: the identity's
 * transaction holds the hash and the cutoff, the sessions' commits inside it,
 * and a failure after that leaves the sessions revoked and the password as it
 * was, so more is ended, never less.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordWriter::class)]
#[CoversClass(PasswordChanges::class)]
final class SeparateConnectionPasswordWriterTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string The frozen time every write happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var string The password the identity starts with. */
    private const string OLD_PASSWORD = 'the old passphrase';

    /**
     * Freeze the clock and create the identity table on the default connection
     * and the session and codes tables on the session connection, which is made
     * the storage connection once the shipped migrations have run on the
     * default one.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        self::createSessionRecordTable('authentication_sessions', 'id', SeparateConnectionSession::CONNECTION);
        self::createCodeTableOn(SeparateConnectionSession::CONNECTION);
    }

    /**
     * Release the clock and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        Schema::dropIfExists('cutoff_identities');

        parent::tearDown();
    }

    /**
     * A reset stores the hash and the cutoff on the identity's connection and
     * revokes the sessions on theirs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetSpansBothConnections(): void
    {
        $identity = $this->seedIdentity();

        $this->seedSession($identity);
        $this->seedSession($identity);

        self::assertSame(2, Auth::passwords('api')->set($identity, 'a brand new passphrase', PasswordFlow::RESET, self::requestClient())->revoked);

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertTrue(app(Hasher::class)->check('a brand new passphrase', $stored->getAuthPassword()));
        self::assertSame(self::NOW, $stored->getTokensValidAfter()?->format('Y-m-d H:i:s'));
        self::assertSame(2, DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('revoked_reason', 'password_reset')->count());
    }

    /**
     * A failure once the sessions' revocation has committed rolls the
     * identity's transaction back, password and cutoff with it, and leaves the
     * sessions revoked; nothing reports a password set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterTheSessionsCommitEndsMoreNeverLess(): void
    {
        $identity = $this->seedIdentity();
        $set      = 0;

        $this->seedSession($identity);

        Event::listen(SessionRevoked::class, static function (): never {
            throw new \RuntimeException('a listener failed');
        });

        Event::listen(PasswordSet::class, static function () use (&$set): void {
            $set++;
        });

        try {
            Auth::passwords('api')->set($identity, 'a brand new passphrase', PasswordFlow::RESET, self::requestClient());
            self::fail('The listener failure was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('a listener failed', $exception->getMessage());
        }

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertTrue(app(Hasher::class)->check(self::OLD_PASSWORD, $stored->getAuthPassword()));
        self::assertNull($stored->getTokensValidAfter());
        self::assertSame(1, DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('revoked_reason', 'password_reset')->count());
        self::assertSame(0, $set);
    }

    /**
     * A change or an establishment of the password of an identity that does not
     * live on the storage connection is refused before anything is counted or
     * written: its password, its sessions' revocations and its cutoff could not
     * commit as one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeOrAnEstablishmentRefusesAnIdentityOffTheStorageConnection(): void
    {
        $identity = $this->seedIdentity();

        $this->seedSession($identity);

        $session = SeparateConnectionSession::query()->sole();
        $calls   = [
            static fn (): mixed => Auth::passwords('api')->change($session, self::OLD_PASSWORD, 'a brand new passphrase', self::requestClient()),
            static fn (): mixed => Auth::passwords('api')->establish($session, 'a brand new passphrase', self::requestClient()),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('An identity off the storage connection was changed.');
            } catch (\LogicException $exception) {
                self::assertStringContainsString('A change of password', $exception->getMessage());
            }
        }

        $stored = DB::table('cutoff_identities')->value('password');

        self::assertIsString($stored);
        self::assertTrue(app(Hasher::class)->check(self::OLD_PASSWORD, $stored));
        self::assertNull(DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * Keep the sessions on their own connection and configure the `api` guard.
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

        $config->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.session.model', SeparateConnectionSession::class);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionCutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('hashing.bcrypt.rounds', 4);
    }

    /**
     * Persist an identity with the old password and no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity
     */
    private function seedIdentity(): SeparateConnectionCutoffIdentity
    {
        return SeparateConnectionCutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => app(Hasher::class)->make(self::OLD_PASSWORD)]);
    }

    /**
     * Persist a live session of the identity on the session connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity  $identity
     * @return void
     */
    private function seedSession(SeparateConnectionCutoffIdentity $identity): void
    {
        $session = new SeparateConnectionSession;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
        ])->save();
    }
}
