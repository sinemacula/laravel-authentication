<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\Transport;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\SessionPreconditions;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

/**
 * Unit tests for the checks the session service makes of what a caller hands
 * it: the principal a session for an externally verified identity is pinned to,
 * whether a reloaded identity is the one that was verified, whether a cookie
 * application's request came from its own site, and the pending credential a
 * pending-session action was handed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPreconditions::class)]
final class SessionPreconditionsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * An identity that owns sessions may be signed in; one that does not is
     * refused as a misconfiguration naming its class. A non-human identity,
     * which owns none, is let through, for the admission to refuse as the
     * result it is.
     *
     * @return void
     */
    public function testOnlyAnIdentityThatOwnsSessionsMayStartASession(): void
    {
        SessionPreconditions::assertHoldsSessions(\Mockery::mock(Identity::class, HasSessions::class));
        SessionPreconditions::assertHoldsSessions(\Mockery::mock(MachineIdentity::class));

        $identity = \Mockery::mock(Identity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(
            'The session service can only start sessions for identities that implement %s; %s does not. '
            . 'Sign this guard\'s identities in with attempt() and issue access tokens instead.',
            HasSessions::class,
            $identity::class,
        ));

        SessionPreconditions::assertHoldsSessions($identity);
    }

    /**
     * The pin is the principal given as the argument, or else the one on the
     * context, or none.
     *
     * @return void
     */
    public function testThePinIsTheArgumentOrElseTheContexts(): void
    {
        $argument  = \Mockery::mock(Principal::class);
        $onContext = \Mockery::mock(Principal::class);
        $client    = new ClientContext(null, null);

        self::assertSame($argument, SessionPreconditions::pinnedPrincipal($argument, new SignInContext($client)));
        self::assertSame($onContext, SessionPreconditions::pinnedPrincipal(null, new SignInContext($client, principal: $onContext)));
        self::assertNull(SessionPreconditions::pinnedPrincipal(null, new SignInContext($client)));
    }

    /**
     * A principal named both as the argument and on the context is refused,
     * even when it is the same one.
     *
     * @return void
     */
    public function testAPrincipalNamedTwiceIsRefused(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Name the principal to start a session as either as the argument or on the context, not both.');

        SessionPreconditions::pinnedPrincipal($principal, new SignInContext(new ClientContext(null, null), principal: $principal));
    }

    /**
     * A session may be started under any sign-in method's name, but under no
     * machine credential kind.
     *
     * @return void
     */
    public function testASessionIsNeverStartedUnderACredentialKind(): void
    {
        SessionPreconditions::assertSessionMethod('sso');
        SessionPreconditions::assertSessionMethod('password');

        foreach (['api_key', 'client_credentials'] as $kind) {
            try {
                SessionPreconditions::assertSessionMethod($kind);

                self::fail("A session was allowed under [{$kind}].");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("[{$kind}] names a machine credential, not a sign-in method; no session can be started with it.", $exception->getMessage());
            }
        }
    }

    /**
     * No session is started or reauthenticated under `external_provider` but by
     * the external sign-in, which records its provenance.
     *
     * @return void
     */
    public function testASessionIsNeverStartedUnderTheExternalProviderMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('[external_provider] is not a sign-in method: only a result an external provider verified signs a session in under it.');

        SessionPreconditions::assertSessionMethod('external_provider');
    }

    /**
     * Rows of `[first factor]`: what only the external sign-in records.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\FirstFactor}>
     */
    public static function provideExternalProviderFactors(): iterable
    {
        $identity = \Mockery::mock(Identity::class);

        yield 'the external provider channel' => [new FirstFactor($identity, new Channel(ChannelKind::EXTERNAL_PROVIDER, 'connection-7'))];
        yield 'the external provider amr value' => [new FirstFactor($identity, new Channel(ChannelKind::UNKNOWN), methods: ['pwd', FirstFactor::EXTERNAL_PROVIDER_METHOD])];
    }

    /**
     * A first factor an application describes may not pass for an external
     * identity provider's: neither its channel nor its private `amr` value.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\FirstFactor  $factor
     * @return void
     */
    #[DataProvider('provideExternalProviderFactors')]
    public function testAnApplicationFactorMayNotPassForAnExternalProvidersOne(FirstFactor $factor): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(SessionPreconditions::EXTERNAL_FACTOR_MESSAGE);

        SessionPreconditions::assertApplicationFactor($factor);
    }

    /**
     * Every other channel, the application's own recovery included, and any
     * other `amr` value pass.
     *
     * @return void
     */
    public function testAnyOtherFactorIsAnApplicationFactor(): void
    {
        $identity = \Mockery::mock(Identity::class);

        foreach (array_filter(ChannelKind::cases(), static fn (ChannelKind $kind): bool => $kind !== ChannelKind::EXTERNAL_PROVIDER) as $kind) {
            SessionPreconditions::assertApplicationFactor(new FirstFactor($identity, new Channel($kind), methods: ['pwd', 'otp']));
        }

        $this->addToAssertionCount(1);
    }

    /**
     * A reloaded identity is the verified one only when it is of the same class
     * and has the same auth identifier, compared as identifiers are.
     *
     * @return void
     */
    public function testTheSameIdentityHasTheSameClassAndIdentifier(): void
    {
        self::assertTrue(SessionPreconditions::isSameIdentity($this->identity(7), $this->identity(7)));
        self::assertTrue(SessionPreconditions::isSameIdentity($this->identity(7), $this->identity('7')));
        self::assertFalse(SessionPreconditions::isSameIdentity($this->identity(7), $this->identity(8)));
        $otherClass = \Mockery::mock(Identity::class, Principal::class);
        $otherClass->shouldReceive('getAuthIdentifier')->andReturn(7);

        self::assertFalse(SessionPreconditions::isSameIdentity($otherClass, $this->identity(7)));
    }

    /**
     * A sign-in method may refuse only with a reason a method may give; any
     * other is reported as the misconfiguration it is, naming the method.
     *
     * @return void
     */
    public function testAMethodMayRefuseOnlyWithAMethodsReason(): void
    {
        $method = \Mockery::mock(SignInMethod::class);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, SessionPreconditions::methodReason($method, FailureReason::INVALID_CREDENTIALS));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(
            'Sign-in method %s refused a sign-in as `identity_inactive`, which only the session service may decide;'
            . ' a method answers `invalid_credentials` or another sign-in method reason.',
            $method::class,
        ));

        SessionPreconditions::methodReason($method, FailureReason::IDENTITY_INACTIVE);
    }

    /**
     * `SessionPreconditions` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionPreconditions::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * A cookie application refuses a client that did not come from a page of
     * its own site as `cross_site_request`, a context without the facts
     * included, and lets a same-site one through; a body application never
     * refuses, whatever the client.
     *
     * @return void
     */
    public function testOnlyACookieApplicationRefusesACrossSiteClient(): void
    {
        $cookie   = new RefreshTokenTransport(new RefreshTokenSettings(Transport::COOKIE, 'refresh_token', null, 'refresh', '/auth', [], 'X-Requested-With'));
        $body     = new RefreshTokenTransport(new RefreshTokenSettings(Transport::BODY, 'refresh_token', null, 'refresh', null, [], 'X-Requested-With'));
        $sameSite = new ClientContext(null, null, 'http://localhost', 'http://localhost', ['x-requested-with']);
        $other    = new ClientContext(null, null, 'https://evil.example.test', 'http://localhost', []);
        $plain    = new ClientContext('203.0.113.7', 'Browser/1.0');

        foreach ([$other, $plain] as $client) {

            $refused = SessionPreconditions::crossSite($cookie, $client);

            self::assertNotNull($refused);
            self::assertSame(FailureReason::CROSS_SITE_REQUEST, $refused->reason);
            self::assertNull($refused->identity);
            self::assertNull(SessionPreconditions::crossSite($body, $client));
        }

        self::assertNull(SessionPreconditions::crossSite($cookie, $sameSite));
        self::assertNull(SessionPreconditions::crossSite($body, $sameSite));
    }

    /**
     * A pending credential handed in is let through as given, a secret or a
     * string alike, and `pending_invalid`, the reason
     * `PendingCredential::extract()` answers, is refused with that reason and
     * nothing else.
     *
     * @return void
     */
    public function testAPendingCredentialPassesAndPendingInvalidIsRefused(): void
    {
        $secret = new Secret('pending-credential');

        self::assertSame($secret, SessionPreconditions::pendingCredential($secret));
        self::assertSame('pending-credential', SessionPreconditions::pendingCredential('pending-credential'));

        $refused = SessionPreconditions::pendingCredential(FailureReason::PENDING_INVALID);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::PENDING_INVALID, $refused->reason);
        self::assertNull($refused->identity);
        self::assertNull($refused->principal);
        self::assertNull($refused->tenant);
        self::assertNull($refused->session);
    }

    /**
     * Rows of `[a reason PendingCredential::extract() never answers]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideForeignPendingReasons(): iterable
    {
        foreach (FailureReason::cases() as $reason) {

            if ($reason === FailureReason::PENDING_INVALID) {
                continue;
            }

            yield $reason->value => [$reason];
        }
    }

    /**
     * Any other reason handed in as a pending credential is the caller's error,
     * naming the reason and what to hand in instead.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideForeignPendingReasons')]
    public function testAnyOtherReasonHandedInAsAPendingCredentialIsTheCallersError(FailureReason $reason): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("A pending credential is never refused as `{$reason->value}`: hand in only what `PendingCredential::extract()` answered.");

        SessionPreconditions::pendingCredential($reason);
    }

    /**
     * Build an identity mock with the auth identifier.
     *
     * @param  int|string  $identifier
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(int|string $identifier): MockInterface
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn($identifier);

        return $identity;
    }
}
