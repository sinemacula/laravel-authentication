<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * Unit tests for how a sign-in through the session service ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInResult::class)]
#[CoversClass(SignedInSession::class)]
final class SignInResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A started session is signed in and carries the session, no reason and no
     * wait.
     *
     * @return void
     */
    public function testASignedInResultCarriesTheSession(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);
        $record    = \Mockery::mock(Model::class, EloquentSession::class);
        $tokens    = new TokenPair('access', 'refresh');
        $session   = new SignedInSession($identity, $principal, $record, $tokens, 'password');
        $result    = SignInResult::signedIn($session);

        self::assertSame(SignInStatus::SIGNED_IN, $result->status);
        self::assertTrue($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame($session, $result->session);
        self::assertFalse($result->isPending());
        self::assertNull($result->pending);
        self::assertNull($result->credential);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);

        self::assertSame($identity, $session->identity);
        self::assertSame($principal, $session->principal);
        self::assertSame($record, $session->record);
        self::assertSame($tokens, $session->tokens);
        self::assertSame('password', $session->method);
    }

    /**
     * A started session says nothing about whether it is new: every sign-in
     * creates one, so the session carries exactly who, as whom, its record, its
     * tokens and how.
     *
     * @return void
     */
    public function testASignedInSessionCarriesNoCreationFlag(): void
    {
        $parameters = (new \ReflectionMethod(SignedInSession::class, '__construct'))->getParameters();

        self::assertSame(
            ['identity', 'principal', 'record', 'tokens', 'method'],
            array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters),
        );
    }

    /**
     * A sign-in whose session waits on requirements is pending: it carries the
     * pending session and the credential the call issued, and neither a session
     * nor a reason; an action on a pending session that leaves it pending
     * carries no credential, the client keeping the one it holds.
     *
     * @return void
     */
    public function testAPendingResultCarriesThePendingSessionAndItsCredential(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $record   = \Mockery::mock(Model::class, EloquentSession::class);
        $pending  = new PendingSession(
            'session-1',
            'api',
            $identity,
            null,
            null,
            [PendingRequirement::MFA, PendingRequirement::PRINCIPAL],
            'password',
            CarbonImmutable::now(),
            $record,
        );
        $issued = SignInResult::pending($pending, 'session-1.secret');
        $kept   = SignInResult::pending($pending);

        self::assertSame(SignInStatus::PENDING, $issued->status);
        self::assertTrue($issued->isPending());
        self::assertFalse($issued->isSignedIn());
        self::assertFalse($issued->isFailed());
        self::assertSame($pending, $issued->pending);
        self::assertSame('session-1.secret', $issued->credential);
        self::assertNull($issued->session);
        self::assertNull($issued->reason);
        self::assertNull($issued->retryAfter);

        self::assertSame($pending, $kept->pending);
        self::assertNull($kept->credential);

        self::assertFalse(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->isPending());
        self::assertNull(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->pending);
        self::assertNull(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->credential);
    }

    /**
     * The credential is a sensitive parameter of the result, so it never shows
     * in a stack trace.
     *
     * @return void
     */
    public function testTheCredentialIsSensitive(): void
    {
        $constructor = new \ReflectionMethod(SignInResult::class, '__construct');
        $credential  = array_values(array_filter($constructor->getParameters(), static fn (\ReflectionParameter $parameter): bool => $parameter->getName() === 'credential'))[0];
        $factory     = (new \ReflectionMethod(SignInResult::class, 'pending'))->getParameters()[1];

        self::assertNotSame([], $credential->getAttributes(\SensitiveParameter::class));
        self::assertNotSame([], $factory->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A failure carries its reason and, when given, the wait, and no session.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $limited = SignInResult::failed(FailureReason::RATE_LIMITED, 30);

        self::assertSame(SignInStatus::FAILED, $limited->status);
        self::assertTrue($limited->isFailed());
        self::assertFalse($limited->isSignedIn());
        self::assertNull($limited->session);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);

        self::assertNull(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->retryAfter);
    }

    /**
     * Rows of `[reason]`: each reason only the server-side event carries.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideConcealedReasons(): iterable
    {
        yield 'account rate limited' => [FailureReason::ACCOUNT_RATE_LIMITED];
        yield 'code expired' => [FailureReason::CODE_EXPIRED];
        yield 'code exhausted' => [FailureReason::CODE_EXHAUSTED];
        yield 'passkey counter regressed' => [FailureReason::PASSKEY_COUNTER_REGRESSED];
    }

    /**
     * A concealed reason (the account's own limit, an expired or exhausted
     * code, a passkey counter that did not advance) is answered as invalid
     * credentials with no wait, so the result never reveals that the account or
     * a code exists.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideConcealedReasons')]
    public function testAConcealedReasonIsAnsweredAsInvalidCredentials(FailureReason $reason): void
    {
        $refused = SignInResult::failed($reason, 30);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertNull($refused->retryAfter);
    }

    /**
     * A reason a sign-in method may give that is not concealed reaches the
     * result as it is.
     *
     * @return void
     */
    public function testAnUnconcealedMethodReasonIsKept(): void
    {
        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, SignInResult::failed(FailureReason::PASSKEY_CHALLENGE_INVALID)->reason);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, SignInResult::failed(FailureReason::IDENTIFIER_UNVERIFIED)->reason);
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(SignInResult::class, '__construct'))->isPrivate());
    }

    /**
     * The statuses' values name how a sign-in ended.
     *
     * @return void
     */
    public function testStatusValues(): void
    {
        $values = array_map(static fn (SignInStatus $status): string => $status->value, SignInStatus::cases());

        self::assertSame(['signed_in', 'pending', 'failed'], $values);
    }
}
