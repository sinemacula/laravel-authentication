<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\Integration\Fixtures\CodeMachineClient;
use Tests\TestCase;

/**
 * Integration tests for the queued delivery of one-time codes: whom the job
 * sends a code to and whom it silently skips, that it sends only the live
 * issuance, that its payload is encrypted on a real queue and runs on a worker,
 * and that on a `sync` connection it runs after the response, never inside the
 * request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendOneTimeCode::class)]
#[CoversClass(CodeService::class)]
#[CoversClass(OneTimeCodeMessage::class)]
final class SendOneTimeCodeTest extends TestCase
{
    use InteractsWithCodeIdentities;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender the job delivers through. */
    private FakeOneTimeCodeSender $sender;

    /**
     * Freeze the clock, create the tables, issue known codes and fake the
     * sender.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        CarbonImmutable::setTestNow($this->now);

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE, '246802']);

        $this->sender = FakeOneTimeCodeSender::fake($this->app);
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();
        Schema::dropIfExists('jobs');

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A sign-in code goes to the active identity the guard's provider finds by
     * the number, which reports it verified: the message carries the guard,
     * purpose, type, number, code, expiry and recipient.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInCodeGoesToTheVerifiedHolderOfTheNumber(): void
    {
        $identity = self::seedCodeIdentity();

        $this->job()->handle(app());

        $message = $this->sender->sent()[0] ?? null;

        self::assertInstanceOf(OneTimeCodeMessage::class, $message);
        self::assertSame(['mobile', CodePurpose::SIGN_IN, 'phone'], [$message->guard, $message->purpose, $message->type]);
        self::assertSame([self::PHONE, self::CODE], [$message->identifier, $message->code]);
        self::assertTrue($this->now->addSeconds(600)->equalTo($message->expiresAt));
        self::assertTrue($identity->is($message->identity));
    }

    /**
     * Rows of `[guard, how the holder of the number is seeded]` for numbers
     * whose code goes to no one.
     *
     * @return iterable<string, array{0: string, 1: \Closure(): mixed}>
     */
    public static function provideIneligibleHolders(): iterable
    {
        yield from [
            'no one has the number'          => ['mobile', static fn (): null => null],
            'an unverified number'           => ['mobile', static fn (): CodeIdentity => self::seedCodeIdentity(verified: false)],
            'an inactive identity'           => ['mobile', static fn (): CodeIdentity => self::seedCodeIdentity(active: false)],
            'a verified machine'             => ['machines', static fn (): CodeIdentity => self::seedCodeIdentity()],
            'an identity that cannot verify' => ['unverifiable', static fn (): CodeIdentity => self::seedCodeIdentity()],
        ];
    }

    /**
     * A sign-in code for a number no one may receive it at is not sent, and
     * nothing says so.
     *
     * @param  string  $guard
     * @param  \Closure(): mixed  $seed
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIneligibleHolders')]
    public function testASignInCodeGoesToNoOneElse(string $guard, \Closure $seed): void
    {
        $seed();

        $this->job($guard)->handle(app());

        self::assertSame(0, $this->sender->count());
    }

    /**
     * A machine identity found by a verified number gets no code because it is
     * a machine: the same row, read as a person, would.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineIsRefusedForBeingAMachine(): void
    {
        self::seedCodeIdentity();

        self::assertInstanceOf(CodeMachineClient::class, $this->freshGuard('machines')->getProvider()->retrieveByCredentials(['phone' => self::PHONE]));

        $this->job('machines')->handle(app());

        self::assertSame(0, $this->sender->count());

        $this->job()->handle(app());

        self::assertSame(1, $this->sender->count());
    }

    /**
     * A sign-in code bound to a look-alike of a verified address, whose lookup
     * finds the address's holder, is not sent; the holder's own address gets
     * its code, at that address in its normal form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInCodeGoesOnlyToTheExactHolderOfTheAddress(): void
    {
        $holder = self::seedCodeIdentity(email: 'ada@example.test');

        $this->configureLookAlikeGuard();

        $lookAlike = CodeBinding::signIn('lookalike', 'email', 'ada@exämple.test');

        (new SendOneTimeCode($lookAlike, $this->issue($lookAlike, $this->now)))->handle(app());

        self::assertSame(0, $this->sender->count());

        $exact = CodeBinding::signIn('lookalike', 'email', 'ada@example.test');

        (new SendOneTimeCode($exact, $this->issue($exact, $this->now)))->handle(app());

        $message = $this->sender->sent()[0] ?? null;

        self::assertSame('ada@example.test', $message?->identifier);
        self::assertTrue($holder->is($message->identity));
    }

    /**
     * Rows of what happens to the issuance before the job runs.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideStaleIssuances(): iterable
    {
        yield from [
            'replaced by a resend' => ['resend'],
            'used'                 => ['use'],
            'expired'              => ['expire'],
            'pruned'               => ['prune'],
        ];
    }

    /**
     * A job whose issuance is no longer the live code sends nothing.
     *
     * @param  string  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideStaleIssuances')]
    public function testOnlyTheLiveIssuanceIsSent(string $change): void
    {
        self::seedCodeIdentity();

        $job = $this->job();

        match ($change) {
            'resend' => $this->issue(CodeBinding::signIn('mobile', 'phone', self::PHONE), $this->now->addSeconds(60)),
            'use'    => DB::table('one_time_codes')->update(['consumed_at' => '2026-04-06 12:00:00']),
            'expire' => CarbonImmutable::setTestNow($this->now->addSeconds(600)),
            default  => DB::table('one_time_codes')->delete(),
        };

        $job->handle(app());

        self::assertSame(0, $this->sender->count());
    }

    /**
     * A verification code goes to the identity it was issued for, while its
     * number is still the one the code is bound to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationCodeGoesToItsIdentity(): void
    {
        $identity = self::seedCodeIdentity(verified: false);
        $job      = $this->verificationJob($identity);

        $job->handle(app());

        self::assertSame(self::CODE, $this->sender->lastCodeFor(self::PHONE, CodePurpose::VERIFY_IDENTIFIER));
        self::assertTrue($identity->is($this->sender->sent()[0]->identity));
    }

    /**
     * A verification code is not sent once the identity's number has changed,
     * or it has none: the code could verify nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationCodeIsNotSentToANumberTheIdentityNoLongerHas(): void
    {
        $identity = self::seedCodeIdentity(verified: false);
        $job      = $this->verificationJob($identity);

        DB::table('code_identities')->update(['phone' => '+447700900124']);

        $job->handle(app());

        DB::table('code_identities')->update(['phone' => null]);

        $job->handle(app());

        self::assertSame(0, $this->sender->count());
    }

    /**
     * A verification job carrying a machine identity, or none, sends nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationCodeGoesToNoMachineAndNoOne(): void
    {
        self::seedCodeIdentity();

        $machine = CodeMachineClient::query()->sole();
        $binding = CodeBinding::verification('mobile', 'phone', self::PHONE, $machine);
        $issued  = $this->issue($binding, $this->now);

        (new SendOneTimeCode($binding, $issued, $machine))->handle(app());
        (new SendOneTimeCode($binding, $issued))->handle(app());

        self::assertSame(0, $this->sender->count());
    }

    /**
     * A sender that fails fails the job; with no sender bound, the job cannot
     * resolve one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSendersFailureFailsTheJob(): void
    {
        self::seedCodeIdentity();

        $job = $this->job();

        app()->instance(OneTimeCodeSender::class, new class implements OneTimeCodeSender {
            /**
             * Fail as a gateway would.
             *
             * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function send(OneTimeCodeMessage $message): void
            {
                throw new \RuntimeException('Gateway unavailable.');
            }
        });

        try {
            $job->handle(app());

            self::fail('The sender\'s failure was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Gateway unavailable.', $exception->getMessage());
        }

        app()->forgetInstance(OneTimeCodeSender::class);
        app()->offsetUnset(OneTimeCodeSender::class);

        $this->expectException(BindingResolutionException::class);

        $job->handle(app());
    }

    /**
     * A sign-in job for a guard that is not a jwt guard is a misconfiguration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInJobForAnotherDriversGuardThrows(): void
    {
        config()->set('auth.guards.session', ['driver' => 'session', 'provider' => 'code_identities']);

        $job = $this->job('session');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [session] is not a jwt guard, so it sends no one-time codes.');

        $job->handle(app());
    }

    /**
     * On a worker-backed connection the job is pushed with its payload
     * encrypted (neither the code nor the number can be read from the queue),
     * and a worker delivers it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnARealQueueThePayloadIsEncryptedAndAWorkerDelivers(): void
    {
        self::createJobsTable();
        self::seedCodeIdentity();

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        $payload = DB::table('jobs')->value('payload');

        self::assertIsString($payload);
        self::assertSame(0, $this->sender->count());

        foreach ([self::CODE, self::PHONE, 'code_hash', 'issueId'] as $secret) {
            self::assertStringNotContainsString($secret, $payload);
        }

        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--stop-when-empty' => true]);

        self::assertSame(self::CODE, $this->sender->lastCodeFor(self::PHONE));
        self::assertSame(0, DB::table('jobs')->count());
    }

    /**
     * A queued verification job whose identity was deleted before it ran is
     * dropped, not failed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobForADeletedIdentityIsDropped(): void
    {
        self::createJobsTable();

        $identity = self::seedCodeIdentity(verified: false);

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);

        $this->codeService()->sendVerification($identity, 'phone');

        $identity->delete();

        $failed = 0;

        Queue::failing(static function () use (&$failed): void {
            $failed++;
        });

        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--stop-when-empty' => true]);

        self::assertSame([0, 0, 0], [$this->sender->count(), DB::table('jobs')->count(), $failed]);
    }

    /**
     * On the `sync` connection delivery never runs inside the request: the
     * request sees nothing sent, and the code arrives once the response is
     * sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnTheSyncConnectionDeliveryRunsAfterTheResponse(): void
    {
        self::seedCodeIdentity();

        $sender = $this->sender;

        Route::post('/codes', static function () use ($sender): array {
            $sent = Auth::codes('mobile')->send('phone_code', ['phone' => self::PHONE])->isSent();

            return ['sent' => $sent, 'delivered' => $sender->count()];
        });

        $this->postJson('/codes')->assertExactJson(['sent' => true, 'delivered' => 0]);

        self::assertSame(self::CODE, $sender->lastCodeFor(self::PHONE));
    }

    /**
     * On a `failover` connection that falls back to `sync` delivery never runs
     * inside the request either: the job is pushed once the response is sent,
     * and when every connection before `sync` fails it runs then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnAFailoverThatFallsBackToSyncDeliveryRunsAfterTheResponse(): void
    {
        self::seedCodeIdentity();

        config()->set('queue.connections.broken', ['driver' => 'database', 'connection' => 'missing', 'table' => 'jobs', 'queue' => 'default']);
        config()->set('queue.connections.failover', ['driver' => 'failover', 'connections' => ['broken', 'sync']]);
        config()->set('authentication.codes.queue.connection', 'failover');

        $sender = $this->sender;

        Route::post('/codes', static function () use ($sender): array {
            $sent = Auth::codes('mobile')->send('phone_code', ['phone' => self::PHONE])->isSent();

            return ['sent' => $sent, 'delivered' => $sender->count()];
        });

        $this->postJson('/codes')->assertExactJson(['sent' => true, 'delivered' => 0]);

        self::assertSame(self::CODE, $sender->lastCodeFor(self::PHONE));
    }

    /**
     * A `failover` connection that falls back to `sync` still hands the job to
     * its first connection that works, once the response is sent, for a worker
     * to deliver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnAFailoverThatFallsBackToSyncTheJobIsPushedAfterTheResponse(): void
    {
        self::createJobsTable();
        self::seedCodeIdentity();

        config()->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
        config()->set('queue.connections.failover', ['driver' => 'failover', 'connections' => ['database', 'sync']]);
        config()->set('authentication.codes.queue.connection', 'failover');

        Route::post('/codes', static function (): array {
            $sent = Auth::codes('mobile')->send('phone_code', ['phone' => self::PHONE])->isSent();

            return ['sent' => $sent, 'pushed' => DB::table('jobs')->count()];
        });

        $this->postJson('/codes')->assertExactJson(['sent' => true, 'pushed' => 0]);

        self::assertSame([1, 0], [DB::table('jobs')->count(), $this->sender->count()]);

        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--stop-when-empty' => true]);

        self::assertSame(self::CODE, $this->sender->lastCodeFor(self::PHONE));
    }

    /**
     * An application that turns dispatching after the response off gets
     * Laravel's synchronous fallback: the code is delivered during the call.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAfterResponseDispatchingTheSyncConnectionDeliversAtOnce(): void
    {
        self::seedCodeIdentity();

        Bus::withoutDispatchingAfterResponses();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(self::CODE, $this->sender->lastCodeFor(self::PHONE));
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

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Create Laravel's database queue table.
     *
     * @return void
     */
    private static function createJobsTable(): void
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
    }

    /**
     * A sign-in delivery job for the number on the guard, for a code issued
     * now.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Codes\SendOneTimeCode
     *
     * @throws \Random\RandomException
     */
    private function job(string $guard = 'mobile'): SendOneTimeCode
    {
        $binding = CodeBinding::signIn($guard, 'phone', self::PHONE);

        return new SendOneTimeCode($binding, $this->issue($binding, $this->now));
    }

    /**
     * A verification delivery job for the identity's number, for a code issued
     * now.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Codes\SendOneTimeCode
     *
     * @throws \Random\RandomException
     */
    private function verificationJob(Identity $identity): SendOneTimeCode
    {
        $binding = CodeBinding::verification('mobile', 'phone', self::PHONE, $identity);

        return new SendOneTimeCode($binding, $this->issue($binding, $this->now), $identity);
    }

    /**
     * Issue a code for the binding at the time.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \Random\RandomException
     */
    private function issue(CodeBinding $binding, CarbonImmutable $at): IssuedCode
    {
        $issued = app(OneTimeCodes::class)->issue($binding, $at);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued;
    }
}
