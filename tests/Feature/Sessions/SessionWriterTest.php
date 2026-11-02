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
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Ramsey\Uuid\Uuid;
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
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSessionDraft;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\EncryptedDescriptionSession;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubSession;

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
#[CoversClass(PendingSessionDraft::class)]
final class SessionWriterTest extends TestCase
{
    use InteractsWithSessionRecords, InteractsWithSessions;

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
        $session  = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context('Laptop', 'macOS'),
            $this->lifetimes(),
            $this->now,
            $origin,
            SignInProof::unattested('password', $this->now),
        );
        $record = Session::query()->whereKey($session->record->getKey())->firstOrFail();
        $claims = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken->reveal(), TokenType::REFRESH);

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
     * A session written under a tenant policy records the version it was
     * checked against, and its first factor under the id the sign-in chose; a
     * writer under none records no version.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRecordsTheTenantPolicyVersionAndItsFirstFactorsId(): void
    {
        $identity = $this->seedIdentity();
        $proof    = SignInProof::unattested('password', $this->now);
        $session  = $this->writer()->underTenantPolicy('v4')->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            $proof,
        );
        $plain = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );

        self::assertSame('v4', Session::query()->whereKey($session->record->getKey())->firstOrFail()->getTenantPolicyVersion());
        self::assertNull(Session::query()->whereKey($plain->record->getKey())->firstOrFail()->getTenantPolicyVersion());
        self::assertTrue(SessionProof::query()->whereKey($proof->id)->where('session_id', IdentifierCoercion::stringify($session->record->getKey()))->exists());
    }

    /**
     * A new session records the tenant its sign-in was admitted in as its
     * active tenant, by identifier, and the access token it is issued names it;
     * one admitted in no tenant records none, and its token names none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateRecordsTheActiveTenant(): void
    {
        $identity = $this->seedIdentity();
        $origin   = new ClientContext('198.51.100.4', 'Origin/2.0');
        $admitted = new Admitted($identity, $identity, new PlainTenantFixture(7));
        $first    = SignInProof::unattested('password', $this->now);
        $second   = SignInProof::unattested('password', $this->now);
        $tenanted = $this->writer()->create($admitted, 'email', $this->context(), $this->lifetimes(), $this->now, $origin, $first);
        $bare     = $this->writer()->create($this->admitted($identity), 'email', $this->context(), $this->lifetimes(), $this->now, $origin, $second);
        $tokens   = Auth::manager()->jwt('api');

        self::assertSame('7', Session::query()->whereKey($tenanted->record->getKey())->firstOrFail()->getTenantId());
        self::assertSame('7', $tokens->parse($tenanted->tokens->accessToken->reveal(), TokenType::ACCESS)['tenant_id'] ?? null);
        self::assertNull(Session::query()->whereKey($bare->record->getKey())->firstOrFail()->getTenantId());
        self::assertArrayNotHasKey('tenant_id', $tokens->parse($bare->tokens->accessToken->reveal(), TokenType::ACCESS) ?? []);
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
            $this->writer()->create(
                new Admitted($identity, $principal, null),
                null,
                $this->context(),
                $this->lifetimes(),
                $this->now,
                $this->context()->client,
                SignInProof::unattested('password', $this->now),
            );
            self::fail('Expected an identity that is not a model to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(sprintf('The session service can only create a session for an Eloquent identity; %s is not a model.', $identity::class), $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * A session a model event cancels is refused rather than issued a pair for
     * a row that was never written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateRefusesASessionAModelEventCancels(): void
    {
        $identity = $this->seedIdentity();

        Session::creating(static fn (): bool => false);

        try {
            $this->writer()->create(
                $this->admitted($identity),
                'email',
                $this->context(),
                $this->lifetimes(),
                $this->now,
                $this->context()->client,
                SignInProof::unattested('password', $this->now),
            );
            self::fail('Expected a cancelled session to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(Session::class . ' was not saved: a model event cancelled the new session, so the sign-in wrote nothing.', $exception->getMessage());
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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $context,
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $later  = $this->now->addHour();
        $origin = new ClientContext('198.51.100.9', 'Origin/3.0');

        $session = $this->writer()->replace(
            $this->admitted($identity)->on($proven),
            null,
            $this->context(),
            $this->lifetimes(),
            $later,
            $origin,
            SignInProof::unattested('sso', $later),
        );

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
        $claims = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken->reveal(), TokenType::REFRESH);

        self::assertNotNull($claims);
        self::assertSame($record->getKey(), $claims['sid']);
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
        self::assertNull($record->getSwitchedAt());
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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $context,
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        $given   = $this->context($givenName, $givenPlatform);
        $session = $this->writer()->replace(
            $this->admitted($identity)->on($proven),
            'email',
            $given,
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );

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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        $proven->mergeCasts(['client_name' => 'integer', 'platform' => 'integer'])->forceFill(['client_name' => '42', 'platform' => '7'])->syncOriginal();

        self::assertSame(42, $proven->getAttribute('client_name'));

        $context = $this->context();
        $session = $this->writer()->replace(
            $this->admitted($identity)->on($proven),
            'email',
            $context,
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );

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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $context,
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = EncryptedDescriptionSession::query()->whereKey($first->record->getKey())->firstOrFail();

        self::assertNotSame('Laptop', $proven->getRawOriginal('client_name'));

        $session = $this->writer()->replace(
            $this->admitted($identity)->on($proven),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );

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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $context,
            $this->lifetimes(),
            $this->now,
            $context->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()
            ->whereKey($first->record->getKey())
            ->select(['id', 'authenticatable_type', 'authenticatable_id', 'principal_type', 'principal_id', 'guard', 'refresh_key', 'revoked_at'])
            ->firstOrFail();

        Model::preventAccessingMissingAttributes();

        try {
            $session = $this->writer()->replace(
                $this->admitted($identity)->on($proven),
                'email',
                $this->context(),
                $this->lifetimes(),
                $this->now,
                $context->client,
                SignInProof::unattested('password', $this->now),
            );
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
            'rotated'                => [['refresh_key' => RefreshTokenHasher::hash('rotated')]],
            'revoked'                => [['revoked_at' => '2026-04-06 12:30:00']],
            'another owner'          => [['authenticatable_id' => '999']],
            'another owner type'     => [['authenticatable_type' => 'Other']],
            'another principal'      => [['principal_id' => '999']],
            'another principal type' => [['principal_type' => 'Other']],
            'another guard'          => [['guard' => 'admin']],
            'returned to pending'    => [['status' => 'pending']],
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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        Session::query()->whereKey($proven->getKey())->update($change);

        $before   = (array) Session::query()->whereKey($proven->getKey())->toBase()->first();
        $digest   = $proven->getRefreshKey();
        $admitted = $this->admitted($identity)->on($proven);

        self::assertNull($this->writer()->replace(
            $admitted,
            null,
            $this->context('New'),
            $this->lifetimes(),
            $this->now->addHour(),
            $this->context()->client,
            SignInProof::unattested('sso', $this->now->addHour()),
        ));
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
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $before = (array) Session::query()->whereKey($proven->getKey())->toBase()->first();

        try {
            $unwritable = (new Admitted($identity, new IntegrationIdentity, null))->on($proven);

            $this->writer()->replace($unwritable, null, $this->context(), $this->lifetimes(), $this->now, $this->context()->client, SignInProof::unattested('sso', $this->now));
            self::fail('Expected issuing the pair to fail.');
        } catch (\InvalidArgumentException) {
            self::assertSame($before, (array) Session::query()->whereKey($proven->getKey())->toBase()->first());
            self::assertSame(1, Session::query()->count());
        }
    }

    /**
     * A replacement a model event cancels rolls back whole: the proven session
     * is not revoked and keeps both digests, and no new session is left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledReplacementLeavesTheProvenSessionLive(): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );
        $proven = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $before = (array) Session::query()->whereKey($proven->getKey())->toBase()->first();

        Session::creating(static fn (): bool => false);

        try {
            $this->writer()->replace(
                $this->admitted($identity)->on($proven),
                null,
                $this->context(),
                $this->lifetimes(),
                $this->now->addHour(),
                $this->context()->client,
                SignInProof::unattested('sso', $this->now->addHour()),
            );
            self::fail('Expected a cancelled replacement to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(Session::class . ' was not saved: a model event cancelled the new session, so the sign-in wrote nothing.', $exception->getMessage());
        }

        self::assertSame($before, (array) Session::query()->whereKey($proven->getKey())->toBase()->first());
        self::assertNotNull($before['refresh_key']);
        self::assertNull($before['revoked_at']);
        self::assertSame(1, Session::query()->count());
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

                $this->writer()->replace($admitted, null, $this->context(), $this->lifetimes(), $this->now, $this->context()->client, SignInProof::unattested('sso', $this->now));
                self::fail('Expected a sign-in on no Eloquent session to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('The session service can only replace an Eloquent session the client proved it holds.', $exception->getMessage());
            }
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * Rows of `[absolute lifetime or null, seconds from now to the context's
     * deadline or null, seconds from now to the expected absolute deadline or
     * null, seconds from now to the expected idle deadline]`.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: ?int, 3: int}>
     */
    public static function provideCaps(): iterable
    {
        yield from [
            'the application limit alone'      => [120, null, 7200, 3600],
            'a deadline before the limit'      => [120, 5400, 5400, 3600],
            'a deadline before the idle limit' => [120, 1800, 1800, 1800],
            'a deadline after the limit'       => [120, 9000, 7200, 3600],
            'a deadline with no limit'         => [null, 5400, 5400, 3600],
            'neither a deadline nor a limit'   => [null, null, null, 3600],
        ];
    }

    /**
     * A new session's absolute deadline is the earlier of the application's
     * limit and the context's deadline, either alone, or none when there is
     * neither, and its idle deadline never passes it; replacing a proven
     * session caps the new one at the context's deadline the same way.
     *
     * @param  ?int  $absolute
     * @param  ?int  $deadlineIn
     * @param  ?int  $absoluteIn
     * @param  int  $idleIn
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCaps')]
    public function testTheSessionIsCappedAtTheContextsDeadline(?int $absolute, ?int $deadlineIn, ?int $absoluteIn, int $idleIn): void
    {
        $identity  = $this->seedIdentity();
        $lifetimes = new TokenLifetimes(5, 60, $absolute, 30);
        $context   = $this->context()->withNotAfter($deadlineIn === null ? null : $this->now->addSeconds($deadlineIn));
        $proof     = SignInProof::unattested('password', $this->now);
        $again     = SignInProof::unattested('password', $this->now);
        $first     = $this->writer()->create($this->admitted($identity), 'email', $context, $lifetimes, $this->now, $context->client, $proof);
        $proven    = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $second    = $this->writer()->replace($this->admitted($identity)->on($proven), 'email', $context, $lifetimes, $this->now, $context->client, $again);

        self::assertNotNull($second);

        foreach ([$first->record, $second->record] as $written) {

            $record = Session::query()->whereKey($written->getKey())->firstOrFail();

            self::assertSame($absoluteIn === null ? null : $this->now->getTimestamp() + $absoluteIn, $record->getAbsoluteExpiresAt()?->getTimestamp());
            self::assertSame($this->now->getTimestamp() + $idleIn, $record->getIdleExpiresAt()?->getTimestamp());
        }
    }

    /**
     * Every session the writer inserts records a generation of its own, a UUID,
     * which the instance it answers holds: the session that replaces a proven
     * one has another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverySessionRecordsAGenerationOfItsOwn(): void
    {
        $identity = $this->seedIdentity();
        $context  = $this->context();
        $proof    = SignInProof::unattested('password', $this->now);
        $again    = SignInProof::unattested('password', $this->now);
        $first    = $this->writer()->create($this->admitted($identity), 'email', $context, $this->lifetimes(), $this->now, $context->client, $proof);
        $proven   = Session::query()->whereKey($first->record->getKey())->firstOrFail();
        $second   = $this->writer()->replace($this->admitted($identity)->on($proven), 'email', $context, $this->lifetimes(), $this->now, $context->client, $again);

        self::assertNotNull($second);

        $stored = [
            Session::query()->whereKey($first->record->getKey())->value('generation'),
            Session::query()->whereKey($second->record->getKey())->value('generation'),
        ];

        self::assertTrue(Str::isUuid($stored[0]) && Str::isUuid($stored[1]));
        self::assertNotSame($stored[0], $stored[1]);
        self::assertSame($stored, [$first->record->getAttribute('generation'), $second->record->getAttribute('generation')]);
    }

    /**
     * A session written under a key an earlier session left proofs and a
     * provenance under, bound to the same owner and guard, counts only its own
     * sign-in's: what the earlier one left is deleted before its first factor
     * is recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionUnderAReusedKeyKeepsOnlyItsOwnProofs(): void
    {
        $identity = $this->seedIdentity();
        $key      = Uuid::uuid7();
        $left     = (string) Str::uuid7();

        DB::table('authentication_proofs')->insert([
            'id'                   => $left,
            'session_id'           => $key->toString(),
            'kind'                 => 'additional_factor',
            'purpose'              => 'step_up',
            'method'               => 'totp',
            'channel_kind'         => 'authenticator_app',
            'methods'              => '["otp"]',
            'accepted'             => true,
            'multifactor'          => true,
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
            'guard'                => 'api',
            'authenticated_at'     => $this->now->subMinute(),
        ]);
        DB::table('authentication_provenance')->insert(['session_id' => $key->toString(), 'connection_id' => 'connection-7']);

        $context = $this->context();
        $proof   = SignInProof::unattested('password', $this->now);

        Str::createUuidsUsingSequence([$key, $key]);

        try {
            $session = $this->writer()->create($this->admitted($identity), 'email', $context, $this->lifetimes(), $this->now, $context->client, $proof);
        } finally {
            Str::createUuidsNormally();
        }

        self::assertSame($key->toString(), IdentifierCoercion::stringify($session->record->getKey()));
        self::assertSame(['first_factor'], DB::table('authentication_proofs')->where('session_id', $key->toString())->pluck('kind')->all());
        self::assertFalse(DB::table('authentication_proofs')->where('id', $left)->exists());
        self::assertFalse(DB::table('authentication_provenance')->where('session_id', $key->toString())->exists());
    }

    /**
     * The writer refuses a context whose deadline is the session's start or
     * earlier, before writing anything: establishment refuses such a sign-in
     * first, so this only guards the writer's own contract.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateRefusesADeadlineThatIsNotAfterTheStart(): void
    {
        $identity = $this->seedIdentity();
        $context  = $this->context()->withNotAfter($this->now);

        try {
            $proof = SignInProof::unattested('password', $this->now);

            $this->writer()->create($this->admitted($identity), 'email', $context, $this->lifetimes(), $this->now, $context->client, $proof);

            self::fail('Expected the writer to refuse the deadline.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Cannot start a session whose deadline is not after its start.', $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * A pending session records what it waits on, the digest of its
     * credential's secret and no refresh credential, the session the client
     * proved and the digest it was proven against, and the slots its sign-in
     * holds, as created and last used by the sign-in's client; its idle
     * deadline is the credential's expiry; its first factor is recorded with
     * it; and its credential is its key and the secret, which only the digest
     * verifies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatePendingWritesAWaitingSessionAndItsCredential(): void
    {
        $identity = $this->seedIdentity();
        $proven   = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );
        $windows = [['ip' => 'window'], ['identifier' => 'window']];

        [$record, $credential] = $this->writer()->createPending(
            new PendingSessionDraft($identity, $identity, null, [PendingRequirement::MFA], 'email', SignInProof::unattested('password', $this->now), $proven->record, $windows),
            $this->context('Laptop', 'macOS'),
            $this->lifetimes(),
            $this->now,
            300,
        );

        [$key, $secret] = explode('.', $credential, 2);

        self::assertSame(IdentifierCoercion::stringify($record->getKey()), $key);

        $row = Session::query()->whereKey($record->getKey())->firstOrFail();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertSame([PendingRequirement::MFA], $row->getRequires());
        self::assertTrue(RefreshTokenHasher::verify($secret, (string) $row->getPendingKey()));
        self::assertNull($row->getRefreshKey());
        self::assertNull($row->getPreviousRefreshKey());
        self::assertSame($proven->record->getKey(), $row->supersedes_session_id);
        self::assertSame($proven->record->getRefreshKey(), $row->supersedes_refresh_key);
        self::assertSame($windows, $row->attempt_windows);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $row->principal_id);
        self::assertNull($row->getTenantId());
        self::assertSame('Laptop', $row->client_name);
        self::assertSame('192.0.2.1', $row->created_ip);
        self::assertSame('192.0.2.1', $row->last_used_ip);
        self::assertSame($this->now->getTimestamp(), $row->getSignedInAt()?->getTimestamp());
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), $row->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addMinutes(120)->getTimestamp(), $row->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame(1, DB::table('authentication_proofs')->where('session_id', $key)->count());
    }

    /**
     * A pending session waiting on a choice records no principal, and one whose
     * absolute deadline comes before its credential's expiry idles out at the
     * absolute deadline; a sign-in that proved nothing and holds no slots
     * records none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatePendingNeverOutlivesTheAbsoluteDeadline(): void
    {
        $identity = $this->seedIdentity();

        [$record] = $this->writer()->createPending(
            new PendingSessionDraft($identity, null, null, [PendingRequirement::PRINCIPAL], null, SignInProof::unattested('sso', $this->now), null, null),
            $this->context()->withNotAfter($this->now->addMinute()),
            $this->lifetimes(),
            $this->now,
            300,
        );

        $row = Session::query()->whereKey($record->getKey())->firstOrFail();

        self::assertNull($row->principal_type);
        self::assertNull($row->principal_id);
        self::assertSame([PendingRequirement::PRINCIPAL], $row->getRequires());
        self::assertNull($row->supersedes_session_id);
        self::assertNull($row->supersedes_refresh_key);
        self::assertNull($row->attempt_windows);
        self::assertSame($this->now->addMinute()->getTimestamp(), $row->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addMinute()->getTimestamp(), $row->getIdleExpiresAt()?->getTimestamp());
    }

    /**
     * A pending session is refused a deadline that is not after its start, as
     * an active one is, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatePendingRefusesADeadlineThatIsNotAfterTheStart(): void
    {
        $identity = $this->seedIdentity();
        $context  = $this->context()->withNotAfter($this->now);

        try {
            $this->writer()->createPending(
                new PendingSessionDraft($identity, $identity, null, [PendingRequirement::MFA], 'email', SignInProof::unattested('password', $this->now), null, null),
                $context,
                $this->lifetimes(),
                $this->now,
                300,
            );

            self::fail('Expected the writer to refuse the deadline.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Cannot start a session whose deadline is not after its start.', $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * Every active session the writer creates records that it is active and
     * waits on nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateRecordsAnActiveSession(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->writer()->create(
            $this->admitted($identity),
            'email',
            $this->context(),
            $this->lifetimes(),
            $this->now,
            $this->context()->client,
            SignInProof::unattested('password', $this->now),
        );
        $row = Session::query()->whereKey($session->record->getKey())->firstOrFail();

        self::assertSame(SessionStatus::ACTIVE, $row->getStatus());
        self::assertSame([], $row->getRequires());
        self::assertNull($row->getPendingKey());
        self::assertNull($row->getTenantId());
    }

    /**
     * The session the writer hands back reads as active and waiting on nothing
     * from what the writer set, also on a session model that gives its columns
     * no defaults, as one an application writes itself may not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewSessionReadsActiveOnAModelWithoutDefaults(): void
    {
        self::createSessionRecordTable('stub_sessions');

        config()->set('authentication.session.model', StubSession::class);

        try {
            $identity = $this->seedIdentity();
            $session  = $this->writer()->create(
                $this->admitted($identity),
                'email',
                $this->context(),
                $this->lifetimes(),
                $this->now,
                $this->context()->client,
                SignInProof::unattested('password', $this->now),
            );

            self::assertInstanceOf(StubSession::class, $session->record);
            self::assertSame(SessionStatus::ACTIVE, $session->record->getStatus());
            self::assertSame([], $session->record->getRequires());
            self::assertNull($session->record->getPendingKey());
            self::assertNull($session->record->getSwitchedAt());
        } finally {
            Schema::dropIfExists('stub_sessions');
        }
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
