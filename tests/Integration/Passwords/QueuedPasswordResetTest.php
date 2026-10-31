<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\TestCase;

/**
 * Integration tests of a password reset's delivery on a worker-backed queue:
 * the job carries a live token or code and the identifier it goes to, so it is
 * stored encrypted with the application key, and a worker then delivers what
 * resets the password.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendPasswordReset::class)]
final class QueuedPasswordResetTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * Rows of each way a reset is delivered.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideChannels(): iterable
    {
        yield from [
            'a link' => ['link'],
            'a code' => ['code'],
        ];
    }

    /**
     * The queued job's stored payload holds neither the token or code nor the
     * identifier, nor any part of the issued secret; a worker then delivers it,
     * and what it delivered resets the password.
     *
     * @param  string  $channel
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChannels')]
    public function testThePayloadIsEncryptedAndAWorkerDelivers(string $channel): void
    {
        $this->useDatabaseQueue();

        self::seedResettable();

        $request = $channel === 'link'
            ? $this->passwords()->sendResetLink(['email' => self::EMAIL])
            : $this->passwords()->sendResetCode('phone', ['phone' => self::PHONE]);

        $payload = DB::table('jobs')->value('payload');

        self::assertTrue($request->isSent());
        self::assertIsString($payload);
        self::assertSame([0, 0], [$this->links->count(), $this->codes->count()]);

        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--stop-when-empty' => true]);

        $secret = $channel === 'link' ? $this->links->lastTokenFor(self::EMAIL) : $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);

        self::assertIsString($secret);
        self::assertSame(0, DB::table('jobs')->count());

        foreach ([$secret, self::EMAIL, self::PHONE, 'IssuedCode', 'issueId', 'identifier'] as $plain) {
            self::assertStringNotContainsString($plain, $payload);
        }

        $result = $channel === 'link'
            ? $this->passwords()->reset(['email' => self::EMAIL, 'token' => $secret, 'password' => self::NEW_PASSWORD])
            : $this->passwords()->resetWithCode('phone', ['phone' => self::PHONE, 'code' => $secret, 'password' => self::NEW_PASSWORD]);

        self::assertSame(ResetStatus::RESET, $result->status);
    }

    /**
     * A reset requested through a guard of another driver that builds the
     * package's jwt guard is bound to the jwt guard it was built for, which
     * only a guard with the `jwt` driver can be, and a worker delivers it
     * through that guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetRequestedThroughAnotherDriversJwtGuardIsDeliveredThroughTheJwtGuard(): void
    {
        $this->useDatabaseQueue();

        $identity = self::seedResettable();

        config()->set('auth.guards.copied', ['driver' => 'copied_jwt', 'provider' => 'password_identities']);

        Auth::extend('copied_jwt', static fn (Application $app): JwtGuard => AuthenticationServiceProvider::createJwtGuard($app, 'web', config()->array('auth.guards.web')));

        self::assertTrue(Auth::passwords('copied')->sendResetLink(['email' => self::EMAIL])->isSent());

        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--stop-when-empty' => true]);

        $link = $this->links->sent()[0] ?? null;

        self::assertNotNull($link);
        self::assertSame('web', $link->guard);
        self::assertTrue($identity->is($link->identity));
        self::assertTrue($this->passwords()->reset(['email' => self::EMAIL, 'token' => $link->token(), 'password' => self::NEW_PASSWORD])->isReset());
    }

    /**
     * Create Laravel's database queue table, dropped with the application, and
     * make it the default queue, which the delivery queue uses when it names
     * none.
     *
     * @return void
     */
    private function useDatabaseQueue(): void
    {
        Schema::create('jobs', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('queue')->index();
            $blueprint->longText('payload');
            $blueprint->unsignedTinyInteger('attempts');
            $blueprint->unsignedInteger('reserved_at')->nullable();
            $blueprint->unsignedInteger('available_at');
            $blueprint->unsignedInteger('created_at');
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists('jobs');
        });

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    }
}
