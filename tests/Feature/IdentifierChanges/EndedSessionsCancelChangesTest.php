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
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordReset;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for what ending an identity's sessions does to its pending
 * identifier changes: every bulk revocation of the identity, whichever method
 * or listener runs it, cancels them, since a change link needs no session and
 * would otherwise let whoever requested it from an ended session move the
 * account to an identifier of theirs. Revoking one device, or a principal's
 * sessions, keeps them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRevocations::class)]
#[CoversClass(RevocationScope::class)]
#[CoversClass(PendingChanges::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversTrait(EndsSessions::class)]
final class EndedSessionsCancelChangesTest extends TestCase
{
    use ChangesIdentifiers;

    /**
     * Start every test from a known moment, with the fakes bound and the route
     * change links point at.
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
            Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

            event(new PasswordReset($identity));
        };

        $revokeAll = static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->revokeDevices($identity, RevocationReason::REVOKED);

        yield from [
            'signing out everywhere'                 => [$everywhere(false)],
            'signing out everywhere but this client' => [$everywhere(true)],
            'revoking every device'                  => [$revokeAll],
            'a password changed'                     => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->passwordChanged($identity)],
            'a password reset'                       => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->passwordReset($identity)],
            'a factor removed'                       => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->factorRemoved($identity)],
            'the identity deactivated'               => [static fn (SessionService $sessions, ChangeableIdentity $identity): int => $sessions->identityDeactivated($identity)],
            'Laravel\'s password reset event'        => [$listener],
        ];
    }

    /**
     * Ending the identity's sessions in bulk cancels each of its pending
     * changes, of every type and through every guard, with the sessions: the
     * link requested from a session that ended, and the code, confirm nothing,
     * and the identifiers are kept. Another identity's pending change stays and
     * confirms.
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
        $link     = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::device(self::seedDevice($identity)), 'email.confirm')->link();

        self::assertIsString($link);
        self::assertTrue($this->changes('admin')->requestByCode($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertTrue($this->changes()->requestByCode($other, 'email', 'grace@new.example.test', Reauthentication::confirmedAt($this->now))->isSent());

        $revoke(Auth::sessions('web'), $identity);

        self::assertSame(1, self::rows('identifier_changes'));
        self::assertNull($this->changes()->pending($identity, 'email'));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByLink(Request::create($link)));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('admin')->confirmByCode($identity, 'phone', self::CODE));
        self::assertSame([self::EMAIL, self::PHONE], [$identity->fresh()?->email, $identity->fresh()?->phone]);
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($other, 'email', '246802'));
    }

    /**
     * Rows of revocations that end less than all of the identity's sessions.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNarrowRevocations(): iterable
    {
        yield from [
            'revoking one device'              => ['revokeDevice'],
            'revoking a principal\'s sessions' => ['revokePrincipalDevices'],
            'the principal deactivated'        => ['principalDeactivated'],
        ];
    }

    /**
     * Revoking one device, or the sessions acting as one of the identity's
     * principals, leaves its other sessions, and with them its pending change,
     * which its link still makes.
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
        $device   = self::seedDevice($identity);
        $link     = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::device($device), 'email.confirm')->link();

        self::assertIsString($link);

        $sessions = Auth::sessions('web');

        match ($revocation) {
            'revokeDevice'           => $sessions->revokeDevice($identity, $device->getKey(), RevocationReason::REVOKED),
            'revokePrincipalDevices' => $sessions->revokePrincipalDevices($identity, RevocationReason::REVOKED),
            default                  => $sessions->principalDeactivated($identity),
        };

        self::assertNotNull($device->fresh()?->revoked_at);
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByLink(Request::create($link)));
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
