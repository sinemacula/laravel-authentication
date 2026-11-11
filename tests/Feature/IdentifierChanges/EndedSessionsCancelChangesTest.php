<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordReset;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessionsOnDeletion;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for what ending an identity's sessions does to its pending
 * identifier changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevocationWriter::class)]
#[CoversClass(RevocationScope::class)]
#[CoversClass(PendingChanges::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversTrait(EndsSessions::class)]
#[CoversTrait(EndsSessionsOnDeletion::class)]
final class EndedSessionsCancelChangesTest extends TestCase
{
    use ChangesIdentifiers;

    /**
     * Freeze the clock and bind the fakes and the route change links point at.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
    }

    /**
     * Drop the table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->stopChanging();

        parent::tearDown();
    }

    /**
     * Rows of each way an identity's sessions end in bulk.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \Tests\Integration\Fixtures\ChangeableIdentity): mixed}>
     */
    public static function provideBulkRevocations(): iterable
    {
        $everywhere = static fn (bool $keep): \Closure => static function (SessionService $sessions, ChangeableIdentity $identity) use ($keep): int {
            Auth::guard('web')->setUser($identity);

            return $sessions->signOutEverywhere($keep);
        };

        $listener = static function (SessionService $sessions, ChangeableIdentity $identity): void {
            Event::listen(PasswordReset::class, RevokeSessionsOnPasswordReset::class);

            event(new PasswordReset($identity));
        };

        $revokeAll = static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->revokeSessions($identity, RevocationReason::REVOKED);
        $removal   = static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->factorRemoved($identity, 'factor-1')->revoked;

        yield from [
            'signing out everywhere'                 => [$everywhere(false)],
            'signing out everywhere but this client' => [$everywhere(true)],
            'revoking every session'                 => [$revokeAll],
            'a password changed'                     => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->passwordChanged($identity)],
            'a password reset'                       => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->passwordReset($identity)],
            'a credential removed'                   => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->credentialRemoved($identity)],
            'a factor removed'                       => [$removal],
            'the factors reset'                      => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->factorReset($identity)],
            'the identity deactivated'               => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->identityDeactivated($identity)],
            'the identity deleted'                   => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->identityDeleted($identity)],
            'Laravel\'s password reset event'        => [$listener],
        ];
    }

    /**
     * Every bulk revocation of the identity cancels its pending changes and
     * leaves other identities' alone.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \Tests\Integration\Fixtures\ChangeableIdentity): mixed  $revoke
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBulkRevocations')]
    public function testEveryBulkRevocationOfTheIdentityCancelsItsChanges(\Closure $revoke): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $other    = self::seedChangeable('grace@example.test');
        $link     = $this->changes()->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            Reauthentication::session(self::seedSession($identity)),
            'email.confirm',
            self::requestClient(),
        )->link()?->reveal();

        self::assertIsString($link);
        self::assertTrue($this->changes('admin')->requestByCode($identity, 'phone', self::NEW_PHONE, self::freshSession($identity, 'admin'), self::requestClient())->isSent());
        self::assertTrue($this->changes()->requestByCode($other, 'email', 'grace@new.example.test', self::freshSession($other), self::requestClient())->isSent());

        $revoke(Auth::sessions('web'), $identity);

        self::assertSame(1, self::rows('identifier_changes'));
        self::assertNull($this->changes()->pending($identity, 'email'));
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('admin')->confirmByCode($identity, 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame([self::EMAIL, self::PHONE], [$identity->fresh()?->email, $identity->fresh()?->phone]);
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($other, 'email', self::changeChallenge($other, 'email'), '246802', self::requestClient())->outcome,
        );
    }

    /**
     * Ending a deleted identity's sessions cancels its pending changes once its
     * row is gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeletionOfAnIdentityWhoseRowIsGoneCancelsItsChanges(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $other    = self::seedChangeable('grace@example.test');

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient())->isSent());
        self::assertTrue($this->changes()->requestByCode($other, 'email', 'grace@new.example.test', self::freshSession($other), self::requestClient())->isSent());

        $identity->delete();

        self::assertSame(1, Auth::sessions('web')->identityDeleted($identity));
        self::assertSame(1, self::rows('identifier_changes'));
        self::assertNull($this->changes()->pending($identity, 'email'));
        self::assertNotNull($this->changes()->pending($other, 'email'));
    }

    /**
     * Rows of revocations that end less than all of the identity's sessions.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNarrowRevocations(): iterable
    {
        yield from [
            'revoking one session'             => ['revokeSession'],
            'revoking a principal\'s sessions' => ['revokePrincipalSessions'],
            'the principal deactivated'        => ['principalDeactivated'],
            'the principal deleted'            => ['principalDeleted'],
        ];
    }

    /**
     * Revoking one session, or one principal's sessions, keeps the pending
     * change.
     *
     * @param  string  $revocation
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNarrowRevocations')]
    public function testARevocationOfLessThanEverySessionKeepsTheChange(string $revocation): void
    {
        $identity = self::seedChangeable();
        $session  = self::seedSession($identity);
        $link     = $this->changes()->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            Reauthentication::session($session),
            'email.confirm',
            self::requestClient(),
        )->link()?->reveal();

        self::assertIsString($link);

        $sessions = Auth::sessions('web');

        match ($revocation) {
            'revokeSession'           => $sessions->revokeSession($identity, $session->getKey(), RevocationReason::REVOKED),
            'revokePrincipalSessions' => $sessions->revokePrincipalSessions($identity, RevocationReason::REVOKED),
            'principalDeactivated'    => $sessions->principalDeactivated($identity),
            default                   => $sessions->principalDeleted($identity),
        };

        self::assertNotNull($session->fresh()?->revoked_at);
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
    }

    /**
     * Register the guards the tests change identifiers through.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }
}
