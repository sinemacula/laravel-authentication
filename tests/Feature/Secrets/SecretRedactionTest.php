<?php

declare(strict_types = 1);

namespace Tests\Feature\Secrets;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\SignsInWithCredentials;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\Concerns\InspectsTraces;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Sessions\FailingSignIn;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests that no secret the package hands out, nor the password a
 * sign-in is given, reaches a trace, a dump of a frame's objects or an event:
 * an exception thrown from a sign-in method, from a listener while a sign-in, a
 * refresh, a switch, an activation, a sign-out or a guard's credential check
 * runs, or from a write while a password is rehashed or a pending session is
 * written or acted on, records every frame's arguments (with
 * `zend.exception_ignore_args` off) and the captures of its closures, and
 * VarDumper shows the whole object graph of each argument as a reporter would;
 * none of them carries a token, a pending credential or the password in clear.
 * Every event those flows dispatch is serialised and dumped as a queued
 * listener would receive it, and carries none either.
 *
 * Each call is made directly rather than through a request, so the trace holds
 * only what the package built: a request's own input is the application's to
 * keep out of its reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Secret::class)]
#[CoversClass(AbstractGuard::class)]
#[CoversClass(PasswordSignIn::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SessionRefresh::class)]
#[CoversClass(SessionWriter::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(SignInRequest::class)]
#[CoversClass(SessionSignOut::class)]
#[CoversTrait(SwitchesSessions::class)]
#[CoversTrait(SignsInWithCredentials::class)]
final class SecretRedactionTest extends TestCase
{
    use InspectsTraces, InteractsWithProofs, InteractsWithSessions;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

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
     * A sign-in method that throws while verifying holds the input only behind
     * the request, so the password is in no frame, capture or dumped object.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInMethodThatThrowsLeavesNoPasswordInTheTrace(): void
    {
        $this->seedIdentity();

        app()->make(SignInMethodManager::class)->extend('trusted', fn (): FailingSignIn => new FailingSignIn);

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->sessions()->signIn('trusted', self::credentials(), self::requestContext()));

        self::assertSame('a bug in the sign-in method for api', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, self::PASSWORD));
    }

    /**
     * A listener on `Login` that throws while a sign-in binds the guard finds
     * the pair already issued, held as secrets: no token and no password is in
     * the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerDuringASignInLeavesNoSecretInTheTrace(): void
    {
        $this->seedIdentity();

        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('a bug in a sign-in listener');
        });

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->sessions()->signIn('password', self::credentials(), self::requestContext()));

        self::assertSame('a bug in a sign-in listener', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, self::anyJwt()));
        self::assertFalse(self::dumpsInTrace($exception, self::PASSWORD));
    }

    /**
     * A listener on `Refreshed` that throws after the rotation leaves neither
     * the refresh token presented nor the new pair in the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerDuringARefreshLeavesNoTokenInTheTrace(): void
    {
        $this->seedIdentity();

        $presented = self::bodyRefreshToken($this->signedIn());

        Event::listen(Refreshed::class, static function (): never {
            throw new \RuntimeException('a bug in a refresh listener');
        });

        $exception = self::withArgumentsInTraces(
            \RuntimeException::class,
            fn (): mixed => $this->sessions()->refresh(PresentedRefreshToken::fromBody($presented), self::requestClient()),
        );

        self::assertSame('a bug in a refresh listener', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, $presented));
        self::assertFalse(self::dumpsInTrace($exception, self::anyJwt()));
    }

    /**
     * A listener on `PrincipalSwitched` that throws after the switch leaves
     * neither the refresh token presented nor the new pair in the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerDuringASwitchLeavesNoTokenInTheTrace(): void
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        $presented = self::bodyRefreshToken($session->tokens);

        Event::listen(PrincipalSwitched::class, static function (): never {
            throw new \RuntimeException('a bug in a switch listener');
        });

        $exception = self::withArgumentsInTraces(
            \RuntimeException::class,
            fn (): mixed => $this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($presented), SwitchTarget::principal($second), self::requestClient()),
        );

        self::assertSame('a bug in a switch listener', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, $presented));
        self::assertFalse(self::dumpsInTrace($exception, self::anyJwt()));
    }

    /**
     * A listener on `Login` that throws while an activation binds the guard
     * leaves neither the pending credential nor the new pair in the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerDuringAnActivationLeavesNoCredentialInTheTrace(): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential->reveal();
        $proof      = self::adapterProof($identity, 'api', $pending->pending->id, Purpose::SIGN_IN);

        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('a bug in an activation listener');
        });

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->sessions()->satisfy($credential, $proof, self::requestClient()));

        self::assertSame('a bug in an activation listener', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, $credential));
        self::assertFalse(self::dumpsInTrace($exception, self::anyJwt()));
    }

    /**
     * A listener on `SessionRevoked` that throws while a guard bound to its
     * session signs out leaves no token of that session in the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerDuringASignOutLeavesNoTokenInTheTrace(): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        self::assertTrue($sessions->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        Event::listen(SessionRevoked::class, static function (): never {
            throw new \RuntimeException('a bug in a sign-out listener');
        });

        $exception = self::withArgumentsInTraces(\RuntimeException::class, static fn (): mixed => $sessions->signOut());

        self::assertSame('a bug in a sign-out listener', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, self::anyJwt()));
    }

    /**
     * A listener on `SessionRevoked` that throws while a refresh token signs
     * its session out leaves neither that token nor any other in the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingListenerDuringASignOutByRefreshTokenLeavesNoTokenInTheTrace(): void
    {
        $this->seedIdentity();

        $presented = (string) $this->signedIn()->refreshToken?->reveal();
        $sessions  = $this->sessions();

        Event::listen(SessionRevoked::class, static function (): never {
            throw new \RuntimeException('a bug in a sign-out listener');
        });

        $exception = self::withArgumentsInTraces(
            \RuntimeException::class,
            static fn (): mixed => $sessions->signOutWith(PresentedRefreshToken::fromBody($presented), self::requestClient()),
        );

        self::assertSame('a bug in a sign-out listener', $exception->getMessage());
        self::assertFalse(self::dumpsInTrace($exception, $presented));
        self::assertFalse(self::dumpsInTrace($exception, self::anyJwt()));
    }

    /**
     * A listener on `Validated` that throws while a guard checks credentials,
     * by `validate()` and by `attempt()`, runs inside the credential timebox's
     * closure: the password is in no frame, capture or dumped object.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingValidatedListenerLeavesNoPasswordInTheTrace(): void
    {
        $this->seedIdentity();

        Event::listen(Validated::class, static function (): never {
            throw new \RuntimeException('a bug in a validated listener');
        });

        $validate = $this->freshGuard();
        $attempt  = $this->freshGuard();

        $exceptions = [
            'validate' => self::withArgumentsInTraces(\RuntimeException::class, static fn (): bool => $validate->validate(self::credentials())),
            'attempt'  => self::withArgumentsInTraces(\RuntimeException::class, static fn (): bool => $attempt->attempt(self::credentials())),
        ];

        foreach ($exceptions as $check => $exception) {
            self::assertSame('a bug in a validated listener', $exception->getMessage(), $check);
            self::assertTrue(self::runsClosure($exception, CredentialTimebox::class, 'run'), $check);
            self::assertFalse(self::dumpsInTrace($exception, self::PASSWORD), $check);
        }
    }

    /**
     * A provider that fails while it rehashes an outdated password, after the
     * sign-in is admitted, fails inside the rehash's closure: the password is
     * in no frame, capture or dumped object.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedRehashLeavesNoPasswordInTheTrace(): void
    {
        $identity = $this->seedIdentity();

        $identity->forceFill(['password' => password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 5])])->save();

        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'update') && str_contains($query->sql, 'integration_identities')) {
                throw new \RuntimeException('the rehash failed');
            }
        });

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->sessions()->signIn('password', self::credentials(), self::requestContext()));

        self::assertSame('the rehash failed', $exception->getMessage());
        self::assertTrue(self::runsClosure($exception, Rehashing::class, 'during'));
        self::assertFalse(self::dumpsInTrace($exception, self::PASSWORD));
    }

    /**
     * A write that fails inside the transaction that acts on a pending session,
     * satisfying its factor, making its choice or discarding it, leaves the
     * pending credential out of the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedWriteWhileActingOnAPendingSessionLeavesNoCredentialInTheTrace(): void
    {
        $identity = $this->seedIdentity();

        [$member, $first] = $this->seedMember();

        $other = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $choosing = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->credential?->reveal();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $satisfying = $this->sessions()->signIn('password', self::credentials(), self::requestContext());
        $discarding = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->credential?->reveal();

        self::assertIsString($choosing);
        self::assertIsString($discarding);
        self::assertNotNull($satisfying->pending);
        self::assertNotNull($satisfying->credential);

        $satisfied = $satisfying->credential->reveal();
        $proof     = self::adapterProof($identity, 'api', $satisfying->pending->id, Purpose::SIGN_IN);

        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'update') && str_contains($query->sql, 'authentication_sessions')) {
                throw new \RuntimeException('the pending session was not written');
            }
        });

        $actions = [
            'satisfy' => [$satisfied, PendingSessions::class, 'atomically', fn (): mixed => $this->sessions()->satisfy($satisfied, $proof, self::requestClient())],
            'choose'  => [$choosing, PendingSessions::class, 'atomically', fn (): mixed => $this->sessions('members')->choose($choosing, $first, self::requestClient())],
            'discard' => [$discarding, Connection::class, 'transaction', fn (): mixed => $this->sessions()->discard($discarding, self::requestClient())],
        ];

        foreach ($actions as $action => [$credential, $class, $function, $act]) {

            $exception = self::withArgumentsInTraces(\RuntimeException::class, $act);

            self::assertSame('the pending session was not written', $exception->getMessage(), $action);
            self::assertTrue(self::runsClosure($exception, $class, $function), $action);
            self::assertFalse(self::dumpsInTrace($exception, $credential), $action);
        }
    }

    /**
     * A pending session whose insert fails, inside the transaction that writes
     * it, leaves the secret of its pending credential out of the trace: no
     * value in a frame, a capture or a dumped object is the secret its stored
     * digest was made from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedPendingInsertLeavesNoCredentialSecretInTheTrace(): void
    {
        $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = '';

        Event::listen('eloquent.creating: ' . Session::class, static function (Session $session) use (&$pending): never {

            $pending = (string) $session->pending_key;

            throw new \RuntimeException('the pending session was not written');
        });

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->sessions()->signIn('password', self::credentials(), self::requestContext()));
        $secret    = static fn (string $value): bool => preg_match_all('/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/', $value, $found) > 0
            && array_filter($found[0], static fn (string $candidate): bool => RefreshTokenHasher::verify($candidate, $pending)) !== [];

        self::assertSame('the pending session was not written', $exception->getMessage());
        self::assertNotSame('', $pending);
        self::assertTrue(self::runsClosure($exception, Connection::class, 'transaction'));
        self::assertFalse(self::dumpsInTrace($exception, $secret));
        self::assertFalse(self::dumpsInTrace($exception, self::PASSWORD));
    }

    /**
     * Every event a sign-in, an activation, two refreshes and a sign-out
     * dispatch, serialised as a queued listener receives it and dumped as a
     * reporter shows it, carries no token, pending credential or password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoEventCarriesASecret(): void
    {
        $identity = $this->seedIdentity();
        $events   = self::recordAuthenticationEvents();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending    = $this->sessions()->signIn('password', self::credentials(), self::requestContext());
        $credential = $pending->credential?->reveal();

        self::assertNotNull($credential);
        self::assertNotNull($pending->pending);

        $active = $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->pending->id, Purpose::SIGN_IN), self::requestClient())->session;

        self::assertNotNull($active);

        $refreshed = $this->sessions()->refresh(self::bodyToken($active->tokens), self::requestClient())->session;

        self::assertNotNull($refreshed);

        $sessions = $this->sessions();

        self::assertTrue($sessions->refresh(self::bodyToken($refreshed->tokens), self::requestClient())->isRefreshed());
        self::assertTrue($sessions->signOut());

        $secrets = [$credential, self::PASSWORD, $active->tokens->accessToken->reveal(), self::bodyRefreshToken($refreshed->tokens)];

        self::assertGreaterThan(10, $events->count());

        foreach ($events as $event) {
            self::assertShowsNone($event, $secrets);
        }
    }

    /**
     * Configure the session guards.
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
     * Record every authentication event dispatched from now on, the package's
     * and Laravel's.
     *
     * @return \ArrayObject<int, object>
     */
    private static function recordAuthenticationEvents(): \ArrayObject
    {
        $events = new \ArrayObject;

        Event::listen('*', static function (string $name, array $payload) use ($events): void {

            foreach ($payload as $event) {

                $class = is_object($event) ? $event::class : '';

                if (!str_starts_with($class, 'SineMacula\Laravel\Authentication\Events\\') && !str_starts_with($class, 'Illuminate\Auth\Events\\')) {
                    continue;
                }

                $events->append($event);
            }
        });

        return $events;
    }

    /**
     * Assert the event, serialised as a queued listener receives it and dumped
     * as a reporter shows it, shows no token and none of the secrets.
     *
     * @param  object  $event
     * @param  list<string>  $secrets
     * @return void
     */
    private static function assertShowsNone(object $event, array $secrets): void
    {
        $dumper = new CliDumper;

        $dumper->setColors(false);

        $shown = serialize($event) . (string) $dumper->dump((new VarCloner)->cloneVar($event), true);

        self::assertFalse(self::anyJwt()($shown), $event::class);

        foreach ($secrets as $secret) {
            self::assertStringNotContainsString($secret, $shown, $event::class);
        }
    }

    /**
     * Whether a frame of the class's method was running a closure it was
     * handed, so the exception was thrown while that closure ran.
     *
     * @param  \Throwable  $exception
     * @param  class-string  $class
     * @param  string  $function
     * @return bool
     */
    private static function runsClosure(\Throwable $exception, string $class, string $function): bool
    {
        foreach ($exception->getTrace() as $frame) {

            $closures = array_filter($frame['args'] ?? [], static fn (mixed $argument): bool => $argument instanceof \Closure);

            if ($frame['function'] === $function && is_a($frame['class'] ?? '', $class, true) && $closures !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sign the identity in and return its pair.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenPair
     *
     * @throws \Throwable
     */
    private function signedIn(): TokenPair
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session->tokens;
    }
}
