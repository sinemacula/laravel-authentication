<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
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
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
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
 * Feature tests for what the identifier change service refuses as a
 * misconfiguration, with an exception, before it counts or writes anything: a
 * guard that is not a jwt guard, an identity that cannot change identifiers, a
 * type it cannot change, malformed settings, no notifier, a link route that
 * cannot carry a change link, and an identity on another connection than the
 * devices.
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
     * Start every test from a known moment, with the fakes bound and the routes
     * links might point at.
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
     * Rows of `[the identity, the exception, its message]`: a machine identity
     * has no identifiers to change, and an identity must be an Eloquent model
     * that can change them.
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
        $proof    = Reauthentication::confirmedAt($this->now);
        $changes  = $this->changes();
        $calls    = [
            static fn (): mixed => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof),
            static fn (): mixed => $changes->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'email.confirm'),
            static fn (): mixed => $changes->confirmByCode($identity, 'email', self::CODE),
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
     * A link that names a machine identity, which a request never signs, is a
     * misconfiguration of the guard's provider.
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

        $this->changes('machines')->confirmByLink(Request::create($link));
    }

    /**
     * Rows of `[type, the exception, its message]`: a type that is not a valid
     * identifier type, and one no normaliser is registered for, so its
     * normalised uniqueness cannot be kept.
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
                'No identifier normaliser is registered for [username], so its identifiers cannot be changed: add one to `authentication.identifiers.normalisers`.',
            ],
        ];
    }

    /**
     * A type the service cannot change is refused by requests, confirmations
     * and the reads, before anything is counted.
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
            $changes->requestByCode($identity, $type, 'ada', Reauthentication::confirmedAt($this->now));
            self::fail('Expected the type to be refused.');
        } catch (\Throwable $e) {
            self::assertInstanceOf($exception, $e);
            self::assertStringContainsString($message, $e->getMessage());
        }

        $this->expectException($exception);

        $changes->confirmByCode($identity, $type, self::CODE);
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
     * Rows of `[setting, value, message]`: settings every change reads, each
     * malformed.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'the change lifetime' => ['authentication.identifier_changes.ttl_seconds', 60, 'authentication.identifier_changes.ttl_seconds must be an integer from 300 to 86400.'],
            'the window'          => ['authentication.identifier_changes.recent_authentication_seconds', 'soon', 'recent_authentication_seconds must be an integer'],
            'the code key'        => ['authentication.codes.key', 'too-short', 'authentication.codes.key must be a string of at least 32 bytes'],
            'the delivery queue'  => ['authentication.delivery.queue.connection', 'missing', 'authentication.delivery.queue.connection must name a connection'],
        ];
    }

    /**
     * A malformed setting fails closed before any statement runs, so before
     * anything is locked, counted or written.
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
            $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm');
            self::fail('Expected the setting to be refused.');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString($message, $e->getMessage());
        }

        self::assertSame([], $statements());
        self::assertSame([0, 0], [DB::table('rate_limits')->count(), DB::table('identifier_changes')->count()]);
    }

    /**
     * A change proven by code reads the code settings first, before any
     * statement runs, so before anything is locked or counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestReadsTheCodeSettings(): void
    {
        $identity   = self::seedChangeable();
        $statements = self::recordStatements();

        config()->set('authentication.codes.length', 4);

        try {
            $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now));
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
    public function testCancellingReadsTheCodeKey(): void
    {
        $identity = self::seedChangeable();

        config()->set('authentication.codes.key', 'too-short');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.codes.key must be a string of at least 32 bytes');

        $this->changes()->cancel($identity, 'email');
    }

    /**
     * Without a notifier no change is requested or confirmed: the old
     * identifier could not be told.
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
                fn (): mixed => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now)),
                fn (): mixed => $this->changes()->confirmByCode($identity, 'email', self::CODE),
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
     * Without a code sender, a change by code is refused before anything is
     * counted or written; a change by link, which the application sends, still
     * starts.
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
            $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now));
            self::fail('A change by code was requested with no sender bound.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'No ' . OneTimeCodeSender::class . ' is bound to deliver the code that proves a new identifier: bind one before changing identifiers by code.',
                $exception->getMessage(),
            );
        }

        self::assertSame([0, 0, 0], [DB::table('rate_limits')->count(), DB::table('one_time_codes')->count(), DB::table('identifier_changes')->count()]);
        self::assertTrue($this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->isSent());
    }

    /**
     * Rows of `[route, parameters, the exception, its message]`: parameters
     * that take a name the link sets, a route that takes one as a placeholder,
     * and a route that does not exist.
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
            $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), $route, $parameters);
            self::fail('Expected the route to be refused.');
        } catch (\Throwable $e) {
            self::assertInstanceOf($exception, $e);
            self::assertSame($message, $e->getMessage());
        }

        self::assertSame([0, 0], [DB::table('rate_limits')->count(), DB::table('identifier_changes')->count()]);
    }

    /**
     * An identity stored on another connection than the devices, the codes and
     * the pending changes cannot have a change confirmed in one transaction, so
     * none is requested or confirmed.
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
            . ChangeableIdentity::class . ' must be on the device model\'s connection: the identity is on [identities], the devices on [testing].';

        foreach (
            [
                fn (): mixed => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now)),
                fn (): mixed => $this->changes()->confirmByCode($identity, 'email', self::CODE),
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
     * A confirmation locks the identity's row as its transaction starts, before
     * it reads the pending change or touches a proof, the lock order a password
     * write follows too, so the two wait for each other rather than deadlock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationLocksTheIdentitysRowFirst(): void
    {
        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now));

        $statements = self::recordStatements();
        $lock       = $identity->newModelQuery()->whereKey($identity->getKey())->lockForUpdate()->limit(1)->toSql();

        $this->changes()->confirmByCode($identity, 'email', self::CODE);

        self::assertSame(['begin', $lock], array_slice($statements(), 0, 2));
        self::assertStringContainsString('identifier_changes', $statements()[2]);
    }

    /**
     * A request locks the identity's row as its transaction starts, before it
     * checks the proof or reads the pending change it replaces, so a password
     * write or a confirmation racing it waits instead of falling in between;
     * so does a cancellation, before it reads the change it deletes.
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

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD))->isSent());
        self::assertSame(['begin', $lock], array_slice($statements(), 0, 2));
        self::assertStringContainsString('rate_limits', $statements()[2]);

        $cancelling = self::recordStatements();

        self::assertTrue($this->changes()->cancel($identity, 'email'));
        self::assertSame(['begin', $lock], array_slice($cancelling(), 0, 2));
        self::assertStringContainsString('identifier_changes', $cancelling()[2]);
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
     * Record from now on each statement run, and `begin` where a transaction
     * starts, in order.
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
