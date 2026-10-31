<?php

declare(strict_types = 1);

namespace Tests\Feature\Runtime;

use Carbon\CarbonImmutable;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\Fixtures\Passwords\RecordingTimebox;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\TestCase;

/**
 * Feature tests of the one credential timebox every check of a secret on a
 * guard shares: `attempt()`, a session service sign-in, a reauthentication and
 * a password reset run in the same box, and whichever of them follows a success
 * that ended the box early waits it out when it fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialTimebox::class)]
#[CoversClass(AbstractGuard::class)]
final class SharedCredentialTimeboxTest extends TestCase
{
    use InteractsWithPasswordResets;

    /** @var int The credential timebox budget, in microseconds. */
    private const int BUDGET = 400000;

    /** @var string A password that is not the identity's. */
    private const string WRONG_PASSWORD = 'not the password';

    /**
     * Every flow of one guard runs its check in the guard's one timebox, and a
     * failure after a success is padded whichever flows the two are: a failed
     * sign-in after a successful `attempt()`, a failed reauthentication after a
     * successful sign-in, a failed reset after a successful reauthentication,
     * and a failed `attempt()` after a successful reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterASuccessIsPaddedWhicheverFlowsTheyAre(): void
    {
        self::seedResettable();

        $token = $this->requestLink();
        $box   = new RecordingTimebox;

        app()->instance(Timebox::class, $box);
        config()->set('authentication.timebox.credentials_microseconds', self::BUDGET);

        $guard    = $this->freshGuard('web');
        $sessions = $guard->sessions();
        $identity = PasswordIdentity::query()->sole();
        $recent   = new RecentAuthentication($guard, app(), 300, CarbonImmutable::now());

        self::assertTrue($guard->attempt(self::credentials(self::EMAIL)));
        self::assertNull($sessions->signIn('password', ['email' => self::EMAIL, 'password' => self::WRONG_PASSWORD])->session);
        self::assertNotNull($sessions->signIn('password', self::credentials(self::EMAIL))->session);
        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $recent->refusal($identity, Reauthentication::password(self::WRONG_PASSWORD), self::CLIENT_IP));
        self::assertNull($recent->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP));
        self::assertFalse(Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD])->isReset());
        self::assertTrue(Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->isReset());
        self::assertFalse($guard->attempt(self::credentials(self::EMAIL)));

        self::assertSame([true, false, true, false, true, false, true, false], $box->endedEarly);
        self::assertCount(4, $box->waits);

        foreach ($box->waits as $wait) {
            self::assertGreaterThan(0, $wait);
            self::assertLessThanOrEqual(self::BUDGET, $wait);
        }
    }
}
