<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use Symfony\Component\Routing\Exception\RouteNotFoundException;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Integration\Fixtures\ChangeableMachine;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests for the misconfigurations the identifier change service refuses
 * before it counts or writes anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(ChangeLinks::class)]
#[CoversClass(AuthManager::class)]
final class IdentifierChangeServiceTest extends TestCase
{
    use ChangesIdentifiers, InteractsWithVerifiableIdentities;

    /**
     * Freeze the clock and bind the fakes and the routes links might point at.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        self::createVerifiableIdentitiesTable();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
        Route::get('/email/confirm/{request}', static fn (): string => 'ok')->name('placeholder.confirm');
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::getSchemaBuilder()->dropIfExists('verifiable_identities');

        $this->stopChanging();

        parent::tearDown();
    }

    /**
     * Only a jwt guard has an identifier change service.
     *
     * @return void
     */
    public function testOnlyAJwtGuardHasTheService(): void
    {
        config()->set('auth.guards.session', ['driver' => 'session', 'provider' => 'changeables']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [session] is not a jwt guard, so it has no identifier change service.');

        Auth::identifierChanges('session');
    }

    /**
     * Rows of `[the identity, the exception, its message]` for identities that
     * cannot change identifiers.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity, 1: class-string<\Throwable>, 2: string}>
     */
    public static function provideUnchangeableIdentities(): iterable
    {
        yield from [
            'a machine identity' => [
                static fn (): Identity => ChangeableMachine::query()->create(['email' => 'robot@example.test']),
                \InvalidArgumentException::class,
                ChangeableMachine::class . ' is a machine identity: it has no identifiers to change.',
            ],
            'an identity that can only verify' => [
                static fn (): Identity => self::seedVerifiableIdentity(),
                \LogicException::class,
                'cannot change identifiers: it must be an Eloquent model that implements',
            ],
            'an identity that is not a model' => [
                static fn (): Identity => new PlainIdentityFixture(1),
                \LogicException::class,
                PlainIdentityFixture::class . ' cannot change identifiers',
            ],
        ];
    }

    /**
     * Every method refuses an identity whose identifiers cannot be changed.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  class-string<\Throwable>  $exception
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnchangeableIdentities')]
    public function testEveryMethodRefusesAnIdentityThatCannotChange(\Closure $identity, string $exception, string $message): void
    {
        $identity = $identity();

        // A non-model identity has no session row, so another's stands in.
        $proof   = self::freshSession($identity instanceof Model ? $identity : self::seedChangeable());
        $changes = $this->changes();
        $calls   = [
            static fn (): mixed => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
            static fn (): mixed => $changes->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'email.confirm', self::requestClient()),
            static fn (): mixed => $changes->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
            static fn (): mixed => $changes->pending($identity, 'email'),
            static fn (): mixed => $changes->cancel($identity, 'email'),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('Expected the identity to be refused.');
            } catch (\Throwable $e) {
                self::assertInstanceOf($exception, $e);
                self::assertStringContainsString($message, $e->getMessage());
            }
        }

        self::assertSame([0, 0], [DB::table('rate_limits')->count(), DB::table('identifier_changes')->count()]);
    }

    /**
     * A link naming a machine identity is refused as a misconfiguration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkToAMachineIdentityIsRefused(): void
    {
        $machine = ChangeableMachine::query()->create(['email' => 'robot@example.test']);
        $link    = URL::temporarySignedRoute('email.confirm', $this->now->addHour(), [
            'guard'    => 'machines',
            'identity' => (string) $machine->id,
            'type'     => 'email',
            'purpose'  => 'change_identifier',
            'request'  => '0195f4a2-7b1c-4000-8000-000000000001',
            'hash'     => hash('sha256', self::NEW_EMAIL),
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('is a machine identity: it has no identifiers to change.');

        $this->changes('machines')->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)));
    }

    /**
     * Rows of `[type, the exception, its message]`: an invalid type and one
     * with no normaliser.
     *
     * @return iterable<string, array{0: string, 1: class-string<\Throwable>, 2: string}>
     */
    public static function provideUnchangeableTypes(): iterable
    {
        yield from [
            'a malformed type' => ['Email', \InvalidArgumentException::class, 'Identifier type [Email] must be a lower-case letter'],
            'no normaliser'    => [
                'username',
                \InvalidArgumentException::class,
                'No identifier normaliser is registered for [username], so its identifiers cannot be changed: add one to `authentication.identifiers.normalizers`.',
            ],
        ];
    }

    /**
     * A type the service cannot change is refused before anything is counted.
     *
     * @param  string  $type
     * @param  class-string<\Throwable>  $exception
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnchangeableTypes')]
    public function testATypeThatCannotChangeIsRefused(string $type, string $exception, string $message): void
    {
        $identity = self::seedChangeable();
        $changes  = $this->changes();

        try {
            $changes->requestByCode($identity, $type, 'ada', self::freshSession($identity), self::requestClient());
            self::fail('Expected the type to be refused.');
        } catch (\Throwable $e) {
            self::assertInstanceOf($exception, $e);
            self::assertStringContainsString($message, $e->getMessage());
        }

        $this->expectException($exception);

        $changes->confirmByCode($identity, $type, self::changeChallenge($identity, $type), self::CODE, self::requestClient());
    }

    /**
     * A malformed type is refused by the reads as well.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReadsRefuseAMalformedType(): void
    {
        $identity = self::seedChangeable();

        foreach ([fn (): mixed => $this->changes()->pending($identity, 'Email'), fn (): mixed => $this->changes()->cancel($identity, 'Email')] as $call) {
            try {
                $call();
                self::fail('Expected the type to be refused.');
            } catch (\InvalidArgumentException $e) {
                self::assertStringStartsWith('Identifier type [Email] must be', $e->getMessage());
            }
        }
    }

    /**
     * Rows of `[setting, value, message]` of malformed settings every change
     * reads.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'the change lifetime' => ['authentication.identifier_changes.ttl_seconds', 60, 'authentication.identifier_changes.ttl_seconds must be an integer from 300 to 86400.'],
            'the freshness'       => ['authentication.freshness', 'soon', 'authentication.freshness must map operation names to their freshness.'],
            'the code key'        => ['authentication.codes.key', 'too-short', 'authentication.codes.key must be a string of at least 32 bytes'],
            'the delivery queue'  => ['authentication.delivery.queue.connection', 'missing', 'authentication.delivery.queue.connection must name a connection'],
        ];
    }

    /**
     * A malformed setting fails closed before any statement runs.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedSettingsFailClosed(string $key, mixed $value, string $message): void
    {
        $identity   = self::seedChangeable();
        $statements = self::recordStatements();

        config()->set($key, $value);

        try {
            $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm', self::requestClient());
            self::fail('Expected the setting to be refused.');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString($message, $e->getMessage());
        }

        self::assertSame([], $statements());
        self::assertSame([0, 0], [DB::table('rate_limits')->count(), DB::table('identifier_changes')->count()]);
    }

    /**
     * A change by code reads the code settings before any statement runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestReadsTheCodeSettings(): void
    {
        $identity   = self::seedChangeable();
        $proof      = self::freshSession($identity);
        $statements = self::recordStatements();

        config()->set('authentication.codes.length', 4);

        try {
            $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient());
            self::fail('Expected the code settings to be refused.');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('authentication.codes.length must be an integer from 6 to 10.', $e->getMessage());
        }

        self::assertSame([], $statements());
        self::assertSame(0, self::rows('rate_limits'));
    }

    /**
     * Cancelling reads the code key first, whether or not a change waits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCancelingReadsTheCodeKey(): void
    {
        $identity = self::seedChangeable();

        config()->set('authentication.codes.key', 'too-short');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.codes.key must be a string of at least 32 bytes');

        $this->changes()->cancel($identity, 'email');
    }

    /**
     * Without a notifier no change is requested or confirmed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeNeedsANotifier(): void
    {
        $identity = self::seedChangeable();

        app()->forgetInstance(IdentifierChangeNotifier::class);
        app()->offsetUnset(IdentifierChangeNotifier::class);

        $message = 'No ' . IdentifierChangeNotifier::class . ' is bound to tell an old identifier of its change: bind one before changing identifiers.';

        foreach (
            [
                fn (): mixed => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient()),
                fn (): mixed => $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
            ] as $call
        ) {
            try {
                $call();
                self::fail('Expected the missing notifier to be refused.');
            } catch (\LogicException $e) {
                self::assertSame($message, $e->getMessage());
            }
        }
    }

    /**
     * Without a code sender a change by code is refused, while a change by link
     * still starts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeByCodeNeedsACodeSender(): void
    {
        $identity = self::seedChangeable();

        app()->forgetInstance(OneTimeCodeSender::class);
        app()->offsetUnset(OneTimeCodeSender::class);

        try {
            $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());
            self::fail('A change by code was requested with no sender bound.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'No ' . OneTimeCodeSender::class . ' is bound to deliver the code that proves a new identifier: bind one before changing identifiers by code.',
                $exception->getMessage(),
            );
        }

        self::assertSame([0, 0, 0], [DB::table('rate_limits')->count(), DB::table('one_time_codes')->count(), DB::table('identifier_changes')->count()]);
        self::assertTrue($this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient())->isSent());
    }

    /**
     * Rows of `[route, parameters, the exception, its message]` that cannot
     * carry a change link.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2: class-string<\Throwable>, 3: string}>
     */
    public static function provideUnusableRoutes(): iterable
    {
        yield from [
            'reserved parameters' => [
                'email.confirm',
                ['request' => 'mine', 'hash' => 'mine', 'locale' => 'en'],
                \InvalidArgumentException::class,
                'Identifier change link parameters may not use the reserved names: request, hash.',
            ],
            'a reserved placeholder' => [
                'placeholder.confirm',
                [],
                \InvalidArgumentException::class,
                'Identifier change route [placeholder.confirm] may not use the reserved names as placeholders: request.',
            ],
            'no such route' => ['missing.route', [], RouteNotFoundException::class, 'Route [missing.route] not defined.'],
        ];
    }

    /**
     * A route that cannot carry a change link is refused before anything is
     * counted or written.
     *
     * @param  string  $route
     * @param  array<string, mixed>  $parameters
     * @param  class-string<\Throwable>  $exception
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnusableRoutes')]
    public function testARouteThatCannotCarryTheLinkIsRefused(string $route, array $parameters, string $exception, string $message): void
    {
        $identity = self::seedChangeable();

        try {
            $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), $route, self::requestClient(), $parameters);
            self::fail('Expected the route to be refused.');
        } catch (\Throwable $e) {
            self::assertInstanceOf($exception, $e);
            self::assertSame($message, $e->getMessage());
        }

        self::assertSame([0, 0], [DB::table('rate_limits')->count(), DB::table('identifier_changes')->count()]);
    }

    /**
     * An identity on another connection than the sessions is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOnAnotherConnectionIsRefused(): void
    {
        config()->set('database.connections.identities', config('database.connections.testing'));

        $identity = self::seedChangeable();

        $identity->setConnection('identities');

        $message = 'An identifier change spends its proof with its change to the identity in one transaction, so '
            . ChangeableIdentity::class . ' must be on the storage connection (`authentication.storage.connection`): the identity is on [identities],'
            . ' the package\'s tables on [testing].';

        foreach (
            [
                fn (): mixed => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient()),
                fn (): mixed => $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
            ] as $call
        ) {
            try {
                $call();
                self::fail('Expected the connection to be refused.');
            } catch (\LogicException $e) {
                self::assertSame($message, $e->getMessage());
            }
        }
    }

    /**
     * A confirmation counts its limits before its transaction, which locks the
     * identity's row first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationLocksTheIdentitysRowFirst(): void
    {
        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());

        $challenge  = self::changeChallenge($identity, 'email');
        $statements = self::recordStatements();
        $lock       = $identity->newModelQuery()->whereKey($identity->getKey())->lockForUpdate()->limit(1)->toSql();

        $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient());

        $recorded = $statements();
        $begin    = array_search('begin', $recorded, true);
        $counted  = static fn (string $sql): bool => str_contains($sql, 'rate_limits') && preg_match('/[`"]hits[`"] - 1/', $sql) !== 1;

        self::assertIsInt($begin);
        self::assertSame([], array_filter(array_slice($recorded, 0, $begin), static fn (string $sql): bool => !$counted($sql)));
        self::assertNotSame([], array_slice($recorded, 0, $begin));
        self::assertSame($lock, $recorded[$begin + 1]);
        self::assertStringContainsString('identifier_changes', $recorded[$begin + 2]);
        self::assertSame([], array_filter(array_slice($recorded, $begin), $counted));
    }

    /**
     * A confirmation by code is rate limited, and a confirmed one gives its
     * slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationIsLimitedAndAConfirmedOneGivesItsSlotsBack(): void
    {
        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());

        $challenge = self::changeChallenge($identity, 'email');
        $hits      = static fn (): int => (int) DB::table('rate_limits')->sum('hits');
        $before    = $hits();

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', $challenge, '000000', self::requestClient())->outcome);
        self::assertSame($before + 2, $hits());

        $statements = self::recordStatements();
        $confirmed  = $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient());
        $released   = array_filter($statements(), static fn (string $sql): bool => str_contains($sql, 'rate_limits') && preg_match('/hits\W* - 1/', $sql) === 1);

        self::assertSame([IdentifierChangeOutcome::CHANGED, null], [$confirmed->outcome, $confirmed->retryAfter]);
        self::assertSame($before + 2, $hits());
        self::assertCount(2, $released);

        config()->set('authentication.rate_limits.identifier_change.per_identifier', ['max' => 1, 'decay_seconds' => 3600]);

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(IdentifierChangeOutcome::RATE_LIMITED, $limited->outcome);
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::RATE_LIMITED], [$failed->flow, $failed->reason]);
        self::assertGreaterThan(0, $limited->retryAfter);
        self::assertSame($failed->retryAfter, $limited->retryAfter);
    }

    /**
     * Rows of `[challenge id or null for the live one, code]` a confirmation
     * refuses as malformed.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideMalformedConfirmations(): iterable
    {
        yield from [
            'a malformed challenge' => ['0195F4A2-7B1C-4000-8000-00000000000A', self::CODE],
            'a malformed code'      => [null, '12345'],
        ];
    }

    /**
     * A malformed confirmation takes and keeps its slots, then is
     * `rate_limited`.
     *
     * @param  ?string  $challengeId
     * @param  string  $code
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedConfirmations')]
    public function testAMalformedConfirmationTakesItsSlotsAndIsThenRateLimited(?string $challengeId, string $code): void
    {
        config()->set('authentication.rate_limits.identifier_change.per_identifier', ['max' => 2, 'decay_seconds' => 3600]);

        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());

        $challenge = $challengeId ?? self::changeChallenge($identity, 'email');
        $hits      = static fn (): int => (int) DB::table('rate_limits')->sum('hits');
        $before    = $hits();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', $challenge, $code, self::requestClient())->outcome);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame($before + 2, $hits());
        self::assertSame(0, self::codeAttempts());

        $this->changes()->confirmByCode($identity, 'email', $challenge, $code, self::requestClient());

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = $this->changes()->confirmByCode($identity, 'email', $challenge, $code, self::requestClient());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(IdentifierChangeOutcome::RATE_LIMITED, $limited->outcome);
        self::assertSame([FailureReason::RATE_LIMITED, $limited->retryAfter], [$failed->reason, $failed->retryAfter]);
        self::assertGreaterThan(0, $limited->retryAfter);
        self::assertSame(0, self::codeAttempts());
    }

    /**
     * A confirmation by code answers and reports as the check of its code does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationByCodeAnswersAsItsCodesCheckDoes(): void
    {
        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());

        $challenge = self::changeChallenge($identity, 'email');
        $hits      = static fn (): int => (int) DB::table('rate_limits')->sum('hits');
        $before    = $hits();
        $confirm   = function (string $challenge) use ($identity): IdentifierChangeOutcome {
            $this->recordEvents([AuthenticationFailed::class]);

            return $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient())->outcome;
        };
        $reported = function (): array {
            $failed = $this->recordedEvent(AuthenticationFailed::class);

            return [$failed->flow, $failed->reason, $failed->challengeId];
        };

        self::assertSame(IdentifierChangeOutcome::INVALID, $confirm('not-a-challenge'));
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, null], $reported());
        self::assertSame($before + 2, $hits());
        self::assertSame(IdentifierChangeOutcome::INVALID, $confirm(self::NO_CHALLENGE));
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, self::NO_CHALLENGE], $reported());

        DB::table('one_time_codes')->update(['attempts' => 5]);

        self::assertSame(IdentifierChangeOutcome::EXHAUSTED, $confirm($challenge));
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::CODE_EXHAUSTED, $challenge], $reported());

        DB::table('one_time_codes')->update(['attempts' => 0, 'expires_at' => '2026-04-06 12:00:00']);

        self::assertSame(IdentifierChangeOutcome::EXPIRED, $confirm($challenge));
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::CODE_EXPIRED, $challenge], $reported());
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
    }

    /**
     * A request and a cancellation lock the identity's row before reading the
     * pending change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestAndACancellationLockTheIdentitysRowFirst(): void
    {
        $identity   = self::seedChangeable();
        $statements = self::recordStatements();
        $lock       = $identity->newModelQuery()->whereKey($identity->getKey())->lockForUpdate()->limit(1)->toSql();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), self::requestClient())->isSent());

        $begin  = array_search('begin', $statements(), true);
        $before = array_slice($statements(), 0, (int) $begin);
        $inside = array_slice($statements(), (int) $begin + 1);

        self::assertIsInt($begin);
        self::assertCount(12, array_filter($before, static fn (string $sql): bool => str_contains($sql, 'rate_limits')));
        self::assertSame([], array_filter($inside, static fn (string $sql): bool => str_contains($sql, 'rate_limits')));
        self::assertSame($lock, $inside[0]);

        $canceling = self::recordStatements();

        self::assertTrue($this->changes()->cancel($identity, 'email'));
        self::assertSame(['begin', $lock], array_slice($canceling(), 0, 2));
        self::assertStringContainsString('identifier_changes', $canceling()[2]);
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

    /**
     * Record each statement run from now on, with `begin` where a transaction
     * starts.
     *
     * @return \Closure(): list<string>
     */
    private static function recordStatements(): \Closure
    {
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        Event::listen(TransactionBeginning::class, static function () use (&$statements): void {
            $statements[] = 'begin';
        });

        return static function () use (&$statements): array {
            return $statements;
        };
    }
}
