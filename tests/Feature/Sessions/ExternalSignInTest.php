<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SignsInExternally;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests for signing in through `Auth::sessions()` with a result an
 * external identity provider verified, which a trusted adapter hands over: only
 * on an application that allows `external_provider`, only for an identity the
 * link contract links the result's connection, issuer and subject to, and
 * otherwise as `start()` signs in, under `external_provider`, with the link's
 * id on the provenance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalSignIn::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(SignsInExternally::class)]
final class ExternalSignInTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

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
     * A linked result signs its identity in at once: the session records
     * `external_provider`, the link contract is asked once with the result's
     * connection, issuer and subject exactly as given, the provenance records
     * the link's id, the reports follow the session and the guard is bound to
     * it. No `Attempting` is dispatched and no attempt is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkedResultSignsItsIdentityIn(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, 'Connection-7 ', 'link-9', 'Subject 1 ');

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldNotReceive('acquire');

        $this->recordEvents([Attempting::class, ExternalResultUnlinked::class, SessionCreated::class, SignedIn::class, Validated::class]);

        $signedIn = $this->sessions()->signInExternally($result);
        $session  = $signedIn->session;

        self::assertTrue($signedIn->isSignedIn());
        self::assertNotNull($session);
        self::assertSame($identity->getKey(), $session->identity->getAuthIdentifier());
        self::assertSame('external_provider', $session->method);
        self::assertSame('external_provider', $session->record->getSignInMethod());
        self::assertSame([['Connection-7 ', self::ISSUER, 'Subject 1 ']], $this->externalLinks()->asked);
        self::assertSame([SessionCreated::class, SignedIn::class, Validated::class], $this->recordedClasses());
        self::assertSame('external_provider', $this->recordedEvent(SignedIn::class)->context->method);
        self::assertSame($identity->getKey(), Auth::guard('api')->id());

        $provenance = SessionProofs::provenance($session->record);

        self::assertNotNull($provenance);
        self::assertSame(['Connection-7 ', 'link-9'], [$provenance->connectionId, $provenance->linkId]);
    }

    /**
     * An application that does not allow `external_provider` refuses every
     * external result as `method_not_allowed` before the link contract is
     * asked, reported by `Failed` and `AuthenticationFailed`, and writes
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatDoesNotAllowExternalSignInRefusesIt(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity);

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        $this->recordEvents([ExternalResultUnlinked::class, Failed::class, AuthenticationFailed::class]);

        $refused = $this->sessions()->signInExternally($result);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $refused->reason);
        self::assertSame([], $this->externalLinks()->asked);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SIGN_IN, FailureReason::METHOD_NOT_ALLOWED, 'external_provider'], [$failed->flow, $failed->reason, $failed->context->method]);
        self::assertNull($failed->context->identity);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * A result the link contract links to no identity reports
     * `ExternalResultUnlinked`, with the guard, the client, the connection and
     * the issuer and no identity, then fails as `external_result_unlinked`,
     * writing nothing and binding nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnlinkedResultIsReportedAndRefused(): void
    {
        $this->externalLinks();

        $this->recordEvents([ExternalResultUnlinked::class, Failed::class, AuthenticationFailed::class, SessionCreated::class]);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT));
        $refused = $this->sessions()->signInExternally(new ExternalResult('connection-7', self::ISSUER, 'nobody'), $context);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $refused->reason);
        self::assertSame([ExternalResultUnlinked::class, Failed::class, AuthenticationFailed::class], $this->recordedClasses());

        $unlinked = $this->recordedEvent(ExternalResultUnlinked::class);

        self::assertSame(['api', self::CLIENT_IP, null], [$unlinked->context->guard, $unlinked->context->client->ip, $unlinked->context->identity]);
        self::assertSame(['connection-7', self::ISSUER], [$unlinked->connectionId, $unlinked->issuer]);
        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull($this->recordedEvent(Failed::class)->user);
        self::assertSame(0, Session::query()->count());
        self::assertFalse(Auth::guard('api')->hasUser());
    }

    /**
     * A result is linked only through the connection, issuer and subject it was
     * linked by: another connection, issuer or subject for the same identity is
     * unlinked, and so is a subject that is the identity's email address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResultIsLinkedOnlyThroughItsOwnConnectionIssuerAndSubject(): void
    {
        $identity = $this->seedIdentity();

        $this->linkedResult($identity, 'connection-7', 'link-1', 'subject-1');

        $results = [
            new ExternalResult('connection-8', self::ISSUER, 'subject-1'),
            new ExternalResult('connection-7', 'https://other.example.test', 'subject-1'),
            new ExternalResult('connection-7', self::ISSUER, 'SUBJECT-1'),
            new ExternalResult('connection-7', self::ISSUER, $identity->email),
        ];

        foreach ($results as $result) {
            self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $this->sessions()->signInExternally($result)->reason);
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * The linked identity is reloaded through the guard's provider: an identity
     * the provider no longer finds is `identity_unknown`, and an inactive one
     * `identity_inactive`, each reported with the method and nothing written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLinkedIdentityIsAdmittedAsStartAdmitsIt(): void
    {
        $gone     = $this->seedIdentity('gone@example.test');
        $inactive = $this->seedIdentity('inactive@example.test', false);
        $results  = [$this->linkedResult($gone, subject: 'gone'), $this->linkedResult($inactive, subject: 'inactive')];

        $gone->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $this->sessions()->signInExternally($results[0])->reason);
        self::assertSame('external_provider', $this->recordedEvent(AuthenticationFailed::class)->context->method);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->sessions()->signInExternally($results[1])->reason);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * The principal the context names is the one the session acts as, and with
     * none named an identity with several principals waits for a choice,
     * pending under `external_provider`, its provenance recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalComesFromTheContextOrIsChosen(): void
    {
        [$member, $membership] = $this->seedMember();

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), principal: $membership);
        $session = $this->sessions('members')->signInExternally($this->linkedResult($member), $context)->session;

        self::assertNotNull($session);
        self::assertSame($membership->getKey(), $session->principal->getPrincipalIdentifier());

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->once()->andReturn(new Requirement(new RequirementPart));

        $this->recordEvents([SessionPending::class]);

        $pending = $this->sessions('members')->signInExternally($this->linkedResult($member), $context);

        self::assertTrue($pending->isPending());
        self::assertSame('external_provider', $pending->pending?->method);
        self::assertSame('external_provider', $this->recordedEvent(SessionPending::class)->context->method);
        self::assertSame(2, SessionProvenance::query()->count());
    }

    /**
     * An external result never arrives as a sign-in's input: `signIn()` with
     * `external_provider` names no registered method and throws before anything
     * is dispatched or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalResultNeverArrivesAsInput(): void
    {
        $this->seedIdentity();

        $this->recordEvents([Attempting::class, AuthenticationFailed::class]);

        try {
            $this->sessions()->signIn(SignInMethodManager::EXTERNAL_METHOD, ['connection' => 'connection-7', 'issuer' => self::ISSUER, 'subject' => 'subject-1']);

            self::fail('An external result was taken as input.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Sign-in method [external_provider] is not registered.', $exception->getMessage());
        }

        self::assertSame([], $this->recorded);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * An exception the link contract throws reaches the caller, and nothing is
     * reported or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptionFromTheLinkContractPropagates(): void
    {
        $failure = new \RuntimeException('The link store is down.');

        $this->externalLinks()->failWith($failure);

        $this->recordEvents([ExternalResultUnlinked::class, AuthenticationFailed::class]);

        try {
            $this->sessions()->signInExternally(new ExternalResult('connection-7', self::ISSUER, 'subject-1'));

            self::fail('The link contract\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame([], $this->recorded);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * A sign-in whose transport is misconfigured fails before the link contract
     * is asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMisconfiguredTransportFailsFirst(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity);

        config()->set('auth.guards.api.refresh_token', ['transport' => 'carrier-pigeon']);

        try {
            $this->sessions()->signInExternally($result);

            self::fail('A misconfigured transport was let through.');
        } catch (\InvalidArgumentException) {
            self::assertSame([], $this->externalLinks()->asked);
        }

        self::assertSame(0, SessionProof::query()->count());
    }

    /**
     * A sign-in that names no context takes the request's client, and the
     * provider's deadline alone caps the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAContextTheRequestsClientIsUsed(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, sessionNotAfter: $this->now->addHours(2));
        $session  = $this->sessions()->signInExternally($result)->session;

        self::assertNotNull($session);
        self::assertSame(self::CLIENT_IP, $session->record->getAttribute($session->record->getCreatedIpName()));
        self::assertSame($this->now->addHours(2)->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * Define the guards the tests sign in through.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Bind a mock in place of the contract.
     *
     * @param  class-string  $contract
     * @return \Mockery\MockInterface
     */
    private function bindMock(string $contract): MockInterface
    {
        $mock = \Mockery::mock($contract);

        assert($this->app !== null);

        $this->app->instance($contract, $mock);

        return $mock;
    }
}
