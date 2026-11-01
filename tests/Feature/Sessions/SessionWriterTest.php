<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session as SessionContract;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\EncryptedDescriptionSession;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for writing a session: creating a session, and replacing a
 * proven one, revoked by a compare-and-swap that applies only to the row as it
 * was proven, in the same transaction as the new session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionWriter::class)]
final class SessionWriterTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A new session records the sign-in, its method and the type of identifier
     * it used, as created from the origin's client and last used by the
     * context's, and is issued a pair at `$now` whose refresh token carries the
     * rotation id the session stores the digest of.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateWritesTheSessionAndIssuesItsPair(): void
    {
        $identity = $this->seedIdentity();
        $origin   = new ClientContext('198.51.100.4', 'Origin/2.0');
        $session  = $this->writer()->create($this->admitted($identity), 'password', 'email', $this->context('Laptop', 'macOS'), $this->lifetimes(), $this->now, $origin);
        $record   = Session::query()->whereKey($session->record->getKey())->firstOrFail();
        $claims   = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken, TokenType::REFRESH);

        self::assertSame('password', $session->method);
        self::assertSame('password', $record->getSignInMethod());
        self::assertSame('email', $record->getSignInIdentifierType());
        self::assertNotNull($claims);
        self::assertSame($this->now->getTimestamp(), $claims['iat']);
        self::assertTrue(RefreshTokenHasher::verify((string) $claims['jti'], (string) $record->getRefreshKey())); // @phpstan-ignore cast.string
        self::assertSame('Laptop', $record->client_name);
        self::assertSame('macOS', $record->platform);
        self::assertSame('198.51.100.4', $record->created_ip);
        self::assertSame('Origin/2.0', $record->created_user_agent);
        self::assertSame('192.0.2.1', $record->last_used_ip);
        self::assertSame('Writer/1.0', $record->last_used_user_agent);
        self::assertSame($this->now->addMinutes(60)->getTimestamp(), $record->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addMinutes(120)->getTimestamp(), $record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * A session can only be owned by an Eloquent identity; anything else is a
     * misconfiguration and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateRefusesAnIdentityThatIsNotAModel(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);

        try {
            $this->writer()->create(new Admitted($identity, $principal, null), 'password', null, $this->context(), $this->lifetimes(), $this->now, $this->context()->client);
            self::fail('Expected an identity that is not a model to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(sprintf('The session service can only create a session for an Eloquent identity; %s is not a model.', $identity::class), $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * Replacing a proven session revokes it as `superseded`, forgetting both of
     * its digests, mirrors that on the in-memory session as persisted, and
     * writes a new session for the sign-in: a new key and rotation id, the new
     * sign-in's method and type of identifier (none included), created from the
     * origin's client, and a session that starts at `$now`. The proven session
     * keeps everything else it recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReplaceRevokesTheProvenSessionAndWritesANewOne(): void
    {
        $identity = $this->seedIdentity();
        $context  = $this->context('Laptop', 'macOS');
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $context, $this->lifetimes(), $this->now, $context->client);
        $proven   = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $later    = $this->now->addHour();
        $origin   = new ClientContext('198.51.100.9', 'Origin/3.0');

        $session = $this->writer()->replace($this->admitted($identity)->on($proven), 'sso', null, $this->context(), $this->lifetimes(), $later, $origin);

        self::assertNotNull($session);
        self::assertNotSame($proven->getKey(), $session->record->getKey());
        self::assertSame('sso', $session->method);
        self::assertFalse($proven->isDirty());
        self::assertSame(2, Session::query()->count());

        $previous = Session::query()->whereKey($proven->getKey())->firstOrFail();

        foreach ([$proven, $previous] as $record) {
            self::assertSame($later->getTimestamp(), $record->getRevokedAt()?->getTimestamp());
            self::assertSame('superseded', $record->getRevokedReason());
            self::assertNull($record->getRefreshKey());
            self::assertNull($record->getPreviousRefreshKey());
        }

        self::assertSame('password', $previous->getSignInMethod());
        self::assertSame('email', $previous->getSignInIdentifierType());
        self::assertSame($this->now->getTimestamp(), $previous->getSignedInAt()?->getTimestamp());

        JWT::$timestamp = $later->getTimestamp();

        $record = Session::query()->whereKey($session->record->getKey())->firstOrFail();
        $claims = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken, TokenType::REFRESH);

        self::assertNotNull($claims);
        self::assertSame($record->getKey(), $claims['did']);
        self::assertSame($later->getTimestamp(), $claims['iat']);
        self::assertTrue(RefreshTokenHasher::verify((string) $claims['jti'], (string) $record->getRefreshKey())); // @phpstan-ignore cast.string
        self::assertFalse(RefreshTokenHasher::verify((string) $claims['jti'], (string) $first->record->getRefreshKey())); // @phpstan-ignore cast.string
        self::assertNull($record->getRevokedAt());
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $record->authenticatable_id);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $record->principal_id);
        self::assertSame('api', $record->getGuard());
        self::assertSame('sso', $record->getSignInMethod());
        self::assertNull($record->getSignInIdentifierType());
        self::assertSame('198.51.100.9', $record->created_ip);
        self::assertSame('Origin/3.0', $record->created_user_agent);
        self::assertSame('192.0.2.1', $record->last_used_ip);
        self::assertSame('Writer/1.0', $record->last_used_user_agent);
        self::assertSame($later->getTimestamp(), $record->getSignedInAt()?->getTimestamp());
        self::assertSame($later->getTimestamp(), $record->getLastUsedAt()?->getTimestamp());
        self::assertNull($record->getPrincipalSwitchedAt());
        self::assertNull($record->getPreviousRefreshKey());
        self::assertSame($later->addMinutes(60)->getTimestamp(), $record->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($later->addMinutes(120)->getTimestamp(), $record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * Rows of `[recorded name, recorded platform, given name, given platform,
     * expected name, expected platform]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: ?string, 3: ?string, 4: ?string, 5: ?string}>
     */
    public static function provideClientDescriptions(): iterable
    {
        yield from [
            'both given'              => ['Laptop', 'macOS', 'Phone', 'iOS', 'Phone', 'iOS'],
            'neither given'           => ['Laptop', 'macOS', null, null, 'Laptop', 'macOS'],
            'only the name given'     => ['Laptop', 'macOS', 'Phone', null, 'Phone', 'macOS'],
            'only the platform given' => ['Laptop', 'macOS', null, 'iOS', 'Laptop', 'iOS'],
            'nothing recorded'        => [null, null, null, null, null, null],
        ];
    }

    /**
     * The new session records the client name and platform the sign-in gives,
     * and, for each it does not give, what the proven session recorded: the
     * client proved it is the same one.
     *
     * @param  ?string  $recordedName
     * @param  ?string  $recordedPlatform
     * @param  ?string  $givenName
     * @param  ?string  $givenPlatform
     * @param  ?string  $expectedName
     * @param  ?string  $expectedPlatform
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideClientDescriptions')]
    public function testReplaceInheritsTheDescriptionsTheSignInDoesNotGive(
        ?string $recordedName,
        ?string $recordedPlatform,
        ?string $givenName,
        ?string $givenPlatform,
        ?string $expectedName,
        ?string $expectedPlatform,
    ): void {
        $identity = $this->seedIdentity();
        $context  = $this->context($recordedName, $recordedPlatform);
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $context, $this->lifetimes(), $this->now, $context->client);
        $proven   = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        $given   = $this->context($givenName, $givenPlatform);
        $session = $this->writer()->replace($this->admitted($identity)->on($proven), 'password', 'email', $given, $this->lifetimes(), $this->now, $context->client);

        self::assertNotNull($session);

        $record = Session::query()->whereKey($session->record->getKey())->firstOrFail();

        self::assertSame($expectedName, $record->client_name);
        self::assertSame($expectedPlatform, $record->platform);
    }

    /**
     * A description the proven session reads as a number, as a custom model
     * that casts it might, is inherited as its text.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReplaceInheritsANumericDescriptionAsText(): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $this->context(), $this->lifetimes(), $this->now, $this->context()->client);
        $proven   = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        $proven->mergeCasts(['client_name' => 'integer', 'platform' => 'integer'])->forceFill(['client_name' => '42', 'platform' => '7'])->syncOriginal();

        self::assertSame(42, $proven->getAttribute('client_name'));

        $context = $this->context();
        $session = $this->writer()->replace($this->admitted($identity)->on($proven), 'password', 'email', $context, $this->lifetimes(), $this->now, $context->client);

        self::assertNotNull($session);

        $record = Session::query()->whereKey($session->record->getKey())->firstOrFail();

        self::assertSame('42', $record->client_name);
        self::assertSame('7', $record->platform);
    }

    /**
     * A description is inherited as the session model reads it, not as it is
     * stored, so a model that encrypts its descriptions encrypts the inherited
     * ones once: the new session reads back what the proven one recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReplaceInheritsTheDescriptionsAsTheModelReadsThem(): void
    {
        config()->set('authentication.session.model', EncryptedDescriptionSession::class);

        $identity = $this->seedIdentity();
        $context  = $this->context('Laptop', 'macOS');
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $context, $this->lifetimes(), $this->now, $context->client);
        $proven   = EncryptedDescriptionSession::query()->whereKey($first->record->getKey())->firstOrFail();

        self::assertNotSame('Laptop', $proven->getRawOriginal('client_name'));

        $session = $this->writer()->replace($this->admitted($identity)->on($proven), 'password', 'email', $this->context(), $this->lifetimes(), $this->now, $context->client);

        self::assertNotNull($session);

        $record = EncryptedDescriptionSession::query()->whereKey($session->record->getKey())->firstOrFail();

        self::assertSame('Laptop', $record->client_name);
        self::assertSame('macOS', $record->platform);
    }

    /**
     * A description the proven session was loaded without is not inherited, and
     * is not asked for, so a model that prevents reading a missing attribute
     * replaces it all the same.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReplaceInheritsNoDescriptionTheProvenSessionWasLoadedWithout(): void
    {
        $identity = $this->seedIdentity();
        $context  = $this->context('Laptop', 'macOS');
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $context, $this->lifetimes(), $this->now, $context->client);
        $proven   = Session::query()
            ->whereKey($first->record->getKey())
            ->select(['id', 'authenticatable_type', 'authenticatable_id', 'principal_type', 'principal_id', 'guard', 'refresh_key', 'revoked_at'])
            ->firstOrFail();

        Model::preventAccessingMissingAttributes();

        try {
            $session = $this->writer()->replace($this->admitted($identity)->on($proven), 'password', 'email', $this->context(), $this->lifetimes(), $this->now, $context->client);
        } finally {
            Model::preventAccessingMissingAttributes(false);
        }

        self::assertNotNull($session);

        $record = Session::query()->whereKey($session->record->getKey())->firstOrFail();

        self::assertNull($record->client_name);
        self::assertNull($record->platform);
        self::assertSame('superseded', Session::query()->whereKey($proven->getKey())->value('revoked_reason'));
    }

    /**
     * Rows of `[change]`: what changed on the row after it was proven.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesSinceTheProof(): iterable
    {
        yield from [
            'rotated'           => [['refresh_key' => RefreshTokenHasher::hash('rotated')]],
            'revoked'           => [['revoked_at' => '2026-04-06 12:30:00']],
            'another owner'     => [['authenticatable_id' => '999']],
            'another principal' => [['principal_id' => '999']],
            'another guard'     => [['guard' => 'admin']],
        ];
    }

    /**
     * A row that changed after it was proven is not replaced: the swap misses,
     * nothing is written or issued, and the in-memory session keeps its state.
     *
     * @param  array<string, mixed>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesSinceTheProof')]
    public function testReplaceMissesARowThatChangedSinceItWasProven(array $change): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $this->context(), $this->lifetimes(), $this->now, $this->context()->client);
        $proven   = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        Session::query()->whereKey($proven->getKey())->update($change);

        $before   = (array) Session::query()->whereKey($proven->getKey())->toBase()->first();
        $digest   = $proven->getRefreshKey();
        $admitted = $this->admitted($identity)->on($proven);

        self::assertNull($this->writer()->replace($admitted, 'sso', null, $this->context('New'), $this->lifetimes(), $this->now->addHour(), $this->context()->client));
        self::assertSame($before, (array) Session::query()->whereKey($proven->getKey())->toBase()->first());
        self::assertSame(1, Session::query()->count());
        self::assertSame($digest, $proven->getRefreshKey());
        self::assertNull($proven->getRevokedReason());
        self::assertSame('password', $proven->getSignInMethod());
    }

    /**
     * A failure while issuing the new session's pair (here a principal whose
     * identifier cannot be written into its claim) rolls the replacement back
     * whole: the proven session stays live at the digest it was proven at, and
     * no new session is left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureWhileIssuingLeavesTheProvenSessionLive(): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->writer()->create($this->admitted($identity), 'password', 'email', $this->context(), $this->lifetimes(), $this->now, $this->context()->client);
        $proven   = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $before   = (array) Session::query()->whereKey($proven->getKey())->toBase()->first();

        try {
            $unwritable = (new Admitted($identity, new IntegrationIdentity, null))->on($proven);

            $this->writer()->replace($unwritable, 'sso', null, $this->context(), $this->lifetimes(), $this->now, $this->context()->client);
            self::fail('Expected issuing the pair to fail.');
        } catch (\InvalidArgumentException) {
            self::assertSame($before, (array) Session::query()->whereKey($proven->getKey())->toBase()->first());
            self::assertSame(1, Session::query()->count());
        }
    }

    /**
     * Only an admitted sign-in on an Eloquent session the client proved can
     * replace one: without a session, or on one that is not an Eloquent
     * session, it is a misconfiguration and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReplaceRefusesASignInOnNoEloquentSession(): void
    {
        $identity = $this->seedIdentity();

        foreach ([null, \Mockery::mock(EloquentSession::class), \Mockery::mock(Model::class, SessionContract::class)] as $record) {
            try {
                $admitted = new Admitted($identity, $identity, null, $record);

                $this->writer()->replace($admitted, 'sso', null, $this->context(), $this->lifetimes(), $this->now, $this->context()->client);
                self::fail('Expected a sign-in on no Eloquent session to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('The session service can only replace an Eloquent session the client proved it holds.', $exception->getMessage());
            }
        }

        self::assertSame(0, Session::query()->count());
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The writer for the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionWriter
     */
    private function writer(): SessionWriter
    {
        return new SessionWriter('api', Auth::manager()->jwt('api'), app(ConnectionResolverInterface::class));
    }

    /**
     * An admitted 2D sign-in of the identity.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted
     */
    private function admitted(IntegrationIdentity $identity): Admitted
    {
        return new Admitted($identity, $identity, null);
    }

    /**
     * A sign-in context from a known client.
     *
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(?string $clientName = null, ?string $platform = null): SignInContext
    {
        return new SignInContext(new ClientContext('192.0.2.1', 'Writer/1.0'), $clientName, $platform);
    }

    /**
     * Lifetimes of an hour idle and two hours absolute.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    private function lifetimes(): TokenLifetimes
    {
        return new TokenLifetimes(5, 60, 120, 30);
    }
}
