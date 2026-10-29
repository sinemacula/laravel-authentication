<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\ResetRequests;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\TestCase;

/**
 * Feature tests of requests for a password reset link or code through
 * `Auth::passwords()`: the same answer and the same queued job for an
 * identifier no one holds, the refusals, the request limits and the resend
 * cooldown, and the misconfigurations that throw before anything is counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetRequests::class)]
#[CoversClass(PasswordService::class)]
final class ResetRequestsTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * A request for an identifier no one holds answers exactly as one for the
     * seeded identity, queues the same delivery job instead of delivering
     * inline, and the job sends nothing for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownIdentifierGetsTheSameAnswerAndAJob(): void
    {
        self::seedResettable();

        config()->set('queue.connections.deliveries', ['driver' => 'database']);
        config()->set('authentication.delivery.queue', ['connection' => 'deliveries', 'name' => 'resets']);

        Queue::fake();

        $known   = $this->passwords()->sendResetLink(['email' => self::EMAIL]);
        $unknown = $this->passwords()->sendResetLink(['email' => 'nobody@example.test']);

        self::assertEquals($known, $unknown);
        self::assertSame([CodeRequestStatus::SENT, null], [$known->status, $known->retryAfter]);
        self::assertTrue($known->isSent());

        Queue::assertPushedOn('resets', SendPasswordReset::class, static fn (SendPasswordReset $job): bool => $job->connection === 'deliveries');
        Queue::assertPushed(SendPasswordReset::class, 2);
        self::assertSame(0, $this->links->count());

        foreach (Queue::pushed(SendPasswordReset::class) as $job) {

            self::assertInstanceOf(SendPasswordReset::class, $job);

            $job->handle(app());
        }

        self::assertSame([self::EMAIL], array_map(static fn ($link): string => $link->identifier, $this->links->sent()));
    }

    /**
     * Rows of a request refused as `identifier_invalid` before anything is
     * issued, and the reason it reports.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordService): mixed, 1: string}>
     */
    public static function provideRefusedRequests(): iterable
    {
        yield from [
            'no identifier'         => [static fn (PasswordService $passwords) => $passwords->sendResetLink([]), 'invalid_credentials'],
            'an identifier list'    => [static fn (PasswordService $passwords) => $passwords->sendResetLink(['email' => [self::EMAIL]]), 'invalid_credentials'],
            'an empty identifier'   => [static fn (PasswordService $passwords) => $passwords->sendResetLink(['email' => '  ']), 'invalid_credentials'],
            'a number not in E.164' => [static fn (PasswordService $passwords) => $passwords->sendResetCode('phone', ['phone' => '07700 900123']), 'invalid_credentials'],
        ];
    }

    /**
     * Each refused request answers `identifier_invalid`, reports
     * `AuthenticationFailed` for the reset flow with the identifier as given,
     * and issues nothing.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordService): mixed  $request
     * @param  string  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedRequests')]
    public function testRefusedRequestsIssueNothing(\Closure $request, string $reason): void
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $answer = $request($this->passwords());
        $event  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertInstanceOf(CodeRequest::class, $answer);

        self::assertSame([CodeRequestStatus::IDENTIFIER_INVALID, null, null], [$answer->status, $answer->expiresAt, $answer->retryAfter]);
        self::assertFalse($answer->isSent());
        self::assertSame([AuthenticationFlow::PASSWORD_RESET, $reason, 'web'], [$event->flow, $event->reason->value, $event->context->guard]);
        self::assertSame(0, DB::table('one_time_codes')->count());
    }

    /**
     * A guard that does not allow passwords sends no reset, whatever the
     * identifier, and counts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardWithoutPasswordsSendsNoReset(): void
    {
        config()->set('auth.guards.web.audience', ['methods' => ['sso']]);

        $this->recordEvents([AuthenticationFailed::class]);

        $answer = $this->passwords()->sendResetLink(['email' => self::EMAIL]);

        self::assertSame(CodeRequestStatus::METHOD_NOT_ALLOWED, $answer->status);
        $event = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(['method_not_allowed', self::EMAIL], [$event->reason->value, $event->identifier]);
        self::assertSame([0, 0], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count()]);
    }

    /**
     * Within the resend cooldown a second request issues nothing and says when
     * another may be made; once the request limit is used up for the
     * identifier, it says how long until the window ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsAreLimitedByTheCooldownAndTheLimit(): void
    {
        config()->set('authentication.rate_limits.password_reset_request.per_identifier', ['max' => 2, 'decay_seconds' => 3600]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertTrue($this->passwords()->sendResetLink(['email' => self::EMAIL])->isSent());

        $cooled = $this->passwords()->sendResetLink(['email' => self::EMAIL]);

        self::assertSame([CodeRequestStatus::RATE_LIMITED, 60], [$cooled->status, $cooled->retryAfter]);

        $limited = $this->passwords()->sendResetLink(['email' => 'Ada@Example.test']);

        self::assertSame(CodeRequestStatus::RATE_LIMITED, $limited->status);
        self::assertSame(1800, $limited->retryAfter);
        self::assertSame(['rate_limited', 'rate_limited'], array_map(static fn (AuthenticationFailed $event): string => $event->reason->value, $this->recorded));
        self::assertSame([60, 1800], array_map(static fn (AuthenticationFailed $event): ?int => $event->retryAfter, $this->recorded));
    }

    /**
     * Rows of a misconfigured reset, and what it throws.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordService): mixed, 1: string}>
     */
    public static function provideMisconfiguredResets(): iterable
    {
        $message = 'Password reset codes need a normaliser registered for identifier type [username] in `authentication.identifiers.normalisers`.';

        yield from [
            'a code type with no normaliser'       => [static fn (PasswordService $passwords) => $passwords->sendResetCode('username', ['username' => 'ada']), $message],
            'a code reset type with no normaliser' => [static fn (PasswordService $passwords) => $passwords->resetWithCode('username', ['username' => 'ada']), $message],
            'an invalid identifier type'           => [static fn (PasswordService $passwords) => $passwords->sendResetCode('Phone', ['Phone' => self::PHONE]), 'Identifier type'],
        ];
    }

    /**
     * Each misconfiguration throws before anything is counted.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordService): mixed  $call
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMisconfiguredResets')]
    public function testMisconfiguredResetsThrow(\Closure $call, string $message): void
    {
        try {
            $call($this->passwords());
            self::fail('The misconfiguration was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith($message, $exception->getMessage());
        }

        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A client the caller names is the one a refusal reports, and the one its
     * limit counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientNamedIsReported(): void
    {
        config()->set('auth.guards.web.audience', ['methods' => ['sso']]);

        $client = new ClientContext('198.51.100.9', 'Kiosk/2.0');

        $this->recordEvents([AuthenticationFailed::class]);

        $this->passwords()->sendResetLink(['email' => self::EMAIL], $client);

        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
    }

    /**
     * Rows of a setting a request reads that is malformed, and the message it
     * fails closed with.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'a code length'    => [['authentication.codes.length' => 4], 'authentication.codes.length must be an integer from 6 to 10.'],
            'a codes key'      => [['authentication.codes.key' => 'short'], 'authentication.codes.key must be a string of at least 32 bytes'],
            'a delivery queue' => [['authentication.delivery.queue.connection' => 'missing'], 'authentication.delivery.queue.connection must name a connection'],
            'a link lifetime'  => [['authentication.passwords.reset.link_ttl_seconds' => 1], 'authentication.passwords.reset.link_ttl_seconds must be an integer'],
        ];
    }

    /**
     * A malformed setting fails a request closed, naming the key, before it is
     * counted.
     *
     * @param  array<string, mixed>  $settings
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedSettingsFailBeforeAnythingIsCounted(array $settings, string $message): void
    {
        config()->set($settings);

        try {
            $this->passwords()->sendResetLink(['email' => self::EMAIL]);
            self::fail('A malformed setting was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith($message, $exception->getMessage());
        }

        self::assertSame(0, DB::table('rate_limits')->count());
    }
}
