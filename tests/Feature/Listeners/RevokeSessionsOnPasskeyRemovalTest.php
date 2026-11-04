<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasskeyRemoval;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\HandleIdentity;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests of the optional `RevokeSessionsOnPasskeyRemoval` listener,
 * registered as an application registers it: removing a passkey ends every
 * session of its owner, once the removal commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnPasskeyRemoval::class)]
final class RevokeSessionsOnPasskeyRemovalTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the tables and register the listener.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Event::listen(PasskeyRemoved::class, RevokeSessionsOnPasskeyRemoval::class);
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
     * Removing a passkey revokes every session of its owner, the one signed in
     * with it and a password session alike, with `factor_removed`; another
     * identity's sessions are left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAPasskeyRevokesEverySessionOfItsOwner(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        $this->seedIdentity('grace@example.test');

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials('grace@example.test'))->isSignedIn());

        Auth::passkeys('api')->remove($identity, $passkey->id);

        $reasons = DB::table('authentication_sessions')->where('authenticatable_id', (string) $identity->id)->pluck('revoked_reason')->all();

        self::assertSame(['factor_removed', 'factor_removed'], $reasons);
        self::assertSame([null], DB::table('authentication_sessions')->where('authenticatable_id', '!=', (string) $identity->id)->pluck('revoked_reason')->all());
    }

    /**
     * A removal that is rolled back revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalThatRollsBackRevokesNothing(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        DB::beginTransaction();

        Auth::passkeys('api')->remove($identity, $passkey->id);

        DB::rollBack();

        self::assertSame([null], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * An event that carries no identity revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventWithoutAnIdentityRevokesNothing(): void
    {
        $this->registerPasskey($this->seedIdentity());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        event(new PasskeyRemoved(new EventContext('api', new ClientContext(null, null), method: 'passkey', credentialId: 'removed')));

        self::assertSame([null], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * An identity a global scope hides from every ordinary query, as a soft
     * delete or a tenant or application scope does, still has every session
     * ended: the identity is read with none of its model's global scopes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityAGlobalScopeHidesHasItsSessionsRevoked(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());

        IntegrationIdentity::addGlobalScope('nobody', static function (Builder $query): void {
            $query->whereRaw('1 = 0');
        });

        try {
            self::assertNull(IntegrationIdentity::query()->find($identity->id));
            self::assertTrue(Auth::passkeys('api')->remove($identity, $passkey->id)->isRemoved());
        } finally {
            IntegrationIdentity::clearBootedModels();
        }

        self::assertSame(['factor_removed', 'factor_removed'], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * An identity named by its alias in the morph map is found through the map.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityNamedByItsMorphAliasHasItsSessionsRevoked(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        Relation::morphMap(['person' => IntegrationIdentity::class]);

        try {
            $context = new EventContext('api', new ClientContext(null, null), $identity, method: 'passkey', credentialId: 'removed');

            event(new PasskeyRemoved($context));
        } finally {
            Relation::morphMap([], false);
        }

        self::assertSame('person', $context->identityType);
        self::assertSame(['factor_removed'], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * An identity authenticated by a column other than its key is read by that
     * column, as its guard's provider reads it: only its own sessions are
     * ended, though its auth identifier is another identity's key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityIsReadByItsAuthIdentifierNotItsKey(): void
    {
        Schema::create('handle_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('handle')->unique();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        try {
            $password = app(Hasher::class)->make(self::PASSWORD);
            $owner    = HandleIdentity::query()->create(['handle' => '2', 'email' => 'ada@example.test', 'password' => $password]);
            $other    = HandleIdentity::query()->create(['handle' => 'grace', 'email' => 'grace@example.test', 'password' => $password]);

            self::assertSame([1, 2], [$owner->id, $other->id]);
            self::assertTrue($this->sessions('handles')->signIn('password', self::credentials())->isSignedIn());
            self::assertTrue($this->sessions('handles')->signIn('password', self::credentials())->isSignedIn());
            self::assertTrue($this->sessions('handles')->signIn('password', self::credentials('grace@example.test'))->isSignedIn());

            event(new PasskeyRemoved(new EventContext('handles', new ClientContext(null, null), $owner, method: 'passkey', credentialId: 'removed')));

            self::assertSame(['factor_removed', 'factor_removed'], DB::table('authentication_sessions')->where('authenticatable_id', '1')->pluck('revoked_reason')->all());
            self::assertSame([null], DB::table('authentication_sessions')->where('authenticatable_id', '2')->pluck('revoked_reason')->all());
        } finally {
            Schema::drop('handle_identities');
        }
    }

    /**
     * Rows of an event that names no identity a passkey could belong to: an
     * identifier no row has, an identity that is not a model, a model that is
     * not an identity (a session row, under its own key), a class that does not
     * exist, and a type without an identifier or an identifier without a type,
     * as a session row can record them.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\IntegrationIdentity): \SineMacula\Laravel\Authentication\Events\EventContext, 1: int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideUnknownIdentities(): iterable
    {
        yield 'an id no row has' => [static fn (IntegrationIdentity $identity): EventContext => self::about($identity->replicate()->forceFill(['id' => $identity->id + 1])), 1];
        yield 'an identity that is not a model' => [static fn (IntegrationIdentity $identity): EventContext => self::about(new PlainIdentityFixture($identity->id)), 0];
        yield 'a model that is not an identity' => [static fn (IntegrationIdentity $identity): EventContext => self::recorded(SessionLookup::model()::class, self::sessionId()), 0];
        yield 'a class that does not exist' => [static fn (IntegrationIdentity $identity): EventContext => self::recorded('Tests\NoSuchIdentity', (string) $identity->id), 0];
        yield 'a type without an identifier' => [static fn (IntegrationIdentity $identity): EventContext => self::about(new IntegrationIdentity), 0];
        yield 'an identifier without a type' => [static fn (IntegrationIdentity $identity): EventContext => self::recorded(null, (string) $identity->id), 0];
    }

    /**
     * An event that names no identity a passkey could belong to revokes
     * nothing, and reads no row unless it names an identity model and a key.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\IntegrationIdentity): \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  int  $reads
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnknownIdentities')]
    public function testAnEventNamingNoIdentityRevokesNothing(\Closure $context, int $reads): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        $event   = new PasskeyRemoved($context($identity));
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        event($event);

        self::assertSame($reads, $queries);
        self::assertSame([null], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * Configure the guards and their relying party.
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

        $config->set('auth.providers.handles', ['driver' => 'model', 'model' => HandleIdentity::class]);
        $config->set('auth.guards.handles', ['driver' => 'jwt', 'provider' => 'handles', 'application' => ['methods' => ['password']]]);
    }

    /**
     * The context of an event about the identity given, from no known client.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function about(Identity $identity): EventContext
    {
        return new EventContext('api', new ClientContext(null, null), $identity, method: 'passkey');
    }

    /**
     * The context of an event about a session row that records the owner type
     * and identifier given, and nothing else.
     *
     * @param  ?string  $type
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private static function recorded(?string $type, string $id): EventContext
    {
        $session = SessionLookup::model();

        $session->setRawAttributes(['authenticatable_type' => $type, 'authenticatable_id' => $id]);

        return new EventContext('api', new ClientContext(null, null), session: $session, method: 'passkey', fromSession: true);
    }

    /**
     * The key of the session the test signed in.
     *
     * @return string
     */
    private static function sessionId(): string
    {
        return IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('id')) ?? '';
    }
}
