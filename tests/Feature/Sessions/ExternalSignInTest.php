<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SignsInExternally;
use SineMacula\Laravel\Authentication\Sessions\ExternalResults;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Sessions\InterruptingFactorPolicy;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of signing in with a result an external identity provider
 * verified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalResults::class)]
#[CoversClass(ExternalSignIn::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(SignInProof::class)]
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
     * A linked result signs its identity in at once, recording the link on the
     * provenance.
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

        $signedIn = $this->sessions()->signInExternally($result, self::requestContext());
        $session  = $signedIn->session;

        self::assertTrue($signedIn->isSignedIn());
        self::assertNotNull($session);
        self::assertSame($identity->getKey(), $session->identity->getAuthIdentifier());
        self::assertSame('external_provider', $session->method);
        self::assertSame('external_provider', $session->record->getSignInMethod());
        self::assertSame([['Connection-7 ', self::ISSUER, 'Subject 1 ', null]], $this->externalLinks()->asked);
        self::assertSame([SessionCreated::class, SignedIn::class, Validated::class], $this->recordedClasses());
        self::assertSame('external_provider', $this->recordedEvent(SignedIn::class)->context->method);
        self::assertSame($identity->getKey(), Auth::guard('api')->id());

        $provenance = SessionProofs::provenance($session->record);

        self::assertNotNull($provenance);
        self::assertSame(['Connection-7 ', 'link-9'], [$provenance->connectionId, $provenance->linkId]);
    }

    /**
     * An application that does not allow `external_provider` refuses every
     * external result.
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

        $refused = $this->sessions()->signInExternally($result, self::requestContext());

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $refused->reason);
        self::assertSame([], $this->externalLinks()->asked);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SIGN_IN, FailureReason::METHOD_NOT_ALLOWED, 'external_provider'], [$failed->flow, $failed->reason, $failed->context->method]);
        EventContextAssertions::assertIdentity(null, $failed->context);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * An unlinked result is reported and refused, writing nothing.
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

        self::assertSame(['api', self::CLIENT_IP, null], [$unlinked->context->guard, $unlinked->context->client->ip, $unlinked->context->identityId]);
        self::assertSame(['connection-7', self::ISSUER], [$unlinked->context->connectionId, $unlinked->issuer]);
        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull($this->recordedEvent(Failed::class)->user);
        self::assertSame(0, Session::query()->count());
        self::assertFalse(Auth::guard('api')->hasUser());
    }

    /**
     * A redemption is reported after the session's own events.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionIsReportedAfterTheSessionsOwnEvents(): void
    {
        $identity = $this->seedIdentity();
        $linked   = $this->linkedResult($identity);
        $result   = new ExternalResult($linked->connectionId, $linked->issuer, $linked->subject, requestReference: 'request-3');

        $this->recordEvents([SessionCreated::class, SignedIn::class, ExternalResultRedeemed::class, AuthenticationFailed::class]);

        $session = $this->sessions()->signInExternally($result, self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame([SessionCreated::class, SignedIn::class, ExternalResultRedeemed::class], $this->recordedClasses());

        $redeemed = $this->recordedEvent(ExternalResultRedeemed::class);

        self::assertSame(AuthenticationFlow::SIGN_IN, $redeemed->flow);
        self::assertSame(['api', 'external_provider'], [$redeemed->context->guard, $redeemed->context->method]);
        self::assertSame(['connection-7', 'request-3'], [$redeemed->context->connectionId, $redeemed->context->requestReference]);
        EventContextAssertions::assertIdentity($identity, $redeemed->context);
        EventContextAssertions::assertPrincipal($identity, $redeemed->context);
        EventContextAssertions::assertSession($session->record, $redeemed->context);
        self::assertSame([null, null], [$this->recordedEvent(SignedIn::class)->context->connectionId, $this->recordedEvent(SignedIn::class)->context->requestReference]);
    }

    /**
     * A redemption given a context binds with that context's client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionGivenAContextBindsWithItsClient(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 0);

        $identity = $this->seedIdentity();
        $context  = new SignInContext(new ClientContext(self::PLAIN_IP, self::PLAIN_AGENT));

        $this->recordEvents([PrincipalAssigned::class, SessionAuthenticated::class]);

        $session = $this->sessions()->signInExternally($this->linkedResult($identity), $context)->session;

        self::assertNotNull($session);
        self::assertSame($context->client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($context->client, $this->recordedEvent(SessionAuthenticated::class)->context->client);

        $row = Session::query()->whereKey($session->record->getSessionIdentifier())->sole();

        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$row->getRawOriginal('last_used_ip'), $row->getRawOriginal('last_used_user_agent')]);
    }

    /**
     * The provider context is recorded and never reported or serialised.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProviderContextIsRecordedButNeverReported(): void
    {
        $identity = $this->seedIdentity();
        $context  = new ProviderContext(['protocol' => 'saml-6c1f', 'link' => ['made' => 'domain-4b7d']]);

        $this->recordEvents([
            SessionCreated::class, SignedIn::class, ExternalResultRedeemed::class, SessionPending::class, AuthenticationFailed::class, ExternalResultUnlinked::class,
        ]);

        $session = $this->sessions()->signInExternally($this->linkedResult($identity, providerContext: $context), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame($context->toArray(), SessionProofs::provenance($session->record)?->providerContext?->toArray());

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        $pending = $this->sessions()->signInExternally($this->linkedResult($identity, providerContext: $context), self::requestContext())->pending;

        self::assertNotNull($pending);
        self::assertSame($context->toArray(), SessionProofs::provenance($pending->session)?->providerContext?->toArray());

        $refused = $this->sessions()->signInExternally(new ExternalResult('connection-7', self::ISSUER, 'nobody', providerContext: $context), self::requestContext());

        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $refused->reason);
        self::assertSame(
            [
                SessionCreated::class, SignedIn::class, ExternalResultRedeemed::class, SessionPending::class, ExternalResultRedeemed::class,
                ExternalResultUnlinked::class, AuthenticationFailed::class,
            ],
            $this->recordedClasses(),
        );

        $serialised = [
            ...array_map(static fn (object $event): string => serialize($event), $this->recorded),
            (string) json_encode($session->record),
            (string) json_encode(SessionProvenance::query()->get()),
        ];

        foreach ($serialised as $value) {
            self::assertStringNotContainsString('saml-6c1f', $value);
            self::assertStringNotContainsString('domain-4b7d', $value);
        }

        self::assertStringContainsString('saml-6c1f', $context->toStored());
        self::assertSame([$context->toStored(), $context->toStored()], DB::table('authentication_provenance')->pluck('provider_context')->all());
    }

    /**
     * A pending redemption is reported and a rolled back one is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingRedemptionIsReportedAndARolledBackOneIsNot(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity);

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        $this->recordEvents([SessionPending::class, ExternalResultRedeemed::class]);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->signInExternally($result, self::requestContext())->isPending());
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());

        $pending = $this->sessions()->signInExternally($result, self::requestContext())->pending;

        self::assertNotNull($pending);
        self::assertSame([SessionPending::class, ExternalResultRedeemed::class], $this->recordedClasses());

        $redeemed = $this->recordedEvent(ExternalResultRedeemed::class);

        EventContextAssertions::assertSession($pending->session, $redeemed->context);
        self::assertSame(['connection-7', null], [$redeemed->context->connectionId, $redeemed->context->requestReference]);
    }

    /**
     * A redemption whose identity is deactivated before its write is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionWhoseIdentityIsDeactivatedBeforeItsWriteIsRefused(): void
    {
        $identity = $this->seedIdentity();

        $change = static fn (): int => IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($change));

        $this->recordEvents([
            AuthenticationFailed::class,
            SessionCreated::class,
            SignedIn::class,
            ExternalResultRedeemed::class,
            SessionRevoked::class,
        ]);

        $refused = $this->sessions()->signInExternally($this->linkedResult($identity), self::requestContext());

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $refused->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame('connection-7', $this->recordedEvent(AuthenticationFailed::class)->context->connectionId);
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, Session::query()->sole()->getRawOriginal('revoked_reason'));
        self::assertTrue(Auth::guard('api')->guest());
    }

    /**
     * A redemption whose check fails to read the identity throws rather than
     * signing in, issuing no tokens.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionWhoseCheckFailsThrowsWithoutSigningIn(): void
    {
        $identity = $this->seedIdentity();

        $armed = new \ArrayObject(['on' => false]);

        DB::listen(static function (QueryExecuted $query) use ($armed): void {
            if ($armed['on'] && str_contains($query->sql, 'integration_identities')) {
                throw new \RuntimeException('The identity read failed.');
            }
        });

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy(static function () use ($armed): void {
            $armed['on'] = true;
        }));

        $this->recordEvents([SessionCreated::class, SignedIn::class, ExternalResultRedeemed::class]);

        try {
            $this->sessions()->signInExternally($this->linkedResult($identity), self::requestContext());

            self::fail('Expected the check to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The identity read failed.', $exception->getMessage());
        } finally {
            $armed['on'] = false;
        }

        self::assertSame([], $this->recordedClasses());
        self::assertTrue(Auth::guard('api')->guest());
    }

    /**
     * A refused redemption names the connection and request reference on every
     * event.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRedemptionNamesTheConnectionAndTheRequest(): void
    {
        $this->externalLinks();

        $this->recordEvents([ExternalResultUnlinked::class, AuthenticationFailed::class, ExternalResultRedeemed::class]);

        $refused = $this->sessions()->signInExternally(new ExternalResult('connection-7', self::ISSUER, 'nobody', requestReference: 'request-9'), self::requestContext());

        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $refused->reason);
        self::assertSame([ExternalResultUnlinked::class, AuthenticationFailed::class], $this->recordedClasses());

        foreach ([$this->recordedEvent(ExternalResultUnlinked::class)->context, $this->recordedEvent(AuthenticationFailed::class)->context] as $context) {
            self::assertSame(['connection-7', 'request-9'], [$context->connectionId, $context->requestReference]);
        }
    }

    /**
     * A result is linked only through its own connection, issuer and subject.
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
            self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $this->sessions()->signInExternally($result, self::requestContext())->reason);
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * The link contract is asked with the subject's NameID format, so a link
     * made for one format never links a subject given in another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLinkContractIsAskedWithTheNameIdFormat(): void
    {
        $identity   = $this->seedIdentity();
        $persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
        $email      = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

        $this->externalLinks()->link($identity, 'link-1', 'connection-7', self::ISSUER, 'subject-1', $persistent);

        $results = [
            new ExternalResult('connection-7', self::ISSUER, 'subject-1', nameIdFormat: $email),
            new ExternalResult('connection-7', self::ISSUER, 'subject-1'),
            new ExternalResult('connection-7', self::ISSUER, 'subject-1', nameIdFormat: $persistent),
        ];

        $reasons = array_map(fn (ExternalResult $result): ?FailureReason => $this->sessions()->signInExternally($result, self::requestContext())->reason, $results);

        self::assertSame([FailureReason::EXTERNAL_RESULT_UNLINKED, FailureReason::EXTERNAL_RESULT_UNLINKED, null], $reasons);
        self::assertSame(
            [['connection-7', self::ISSUER, 'subject-1', $email], ['connection-7', self::ISSUER, 'subject-1', null], ['connection-7', self::ISSUER, 'subject-1', $persistent]],
            $this->externalLinks()->asked,
        );
        self::assertSame(1, Session::query()->count());
    }

    /**
     * The linked identity is reloaded and admitted as `start()` admits it.
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

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $this->sessions()->signInExternally($results[0], self::requestContext())->reason);
        self::assertSame('external_provider', $this->recordedEvent(AuthenticationFailed::class)->context->method);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->sessions()->signInExternally($results[1], self::requestContext())->reason);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * The principal comes from the context or waits for a choice.
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
     * `signIn()` with `external_provider` throws before anything is dispatched
     * or written.
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
            $this->sessions()->signIn(
                SignInMethodManager::EXTERNAL_METHOD,
                ['connection' => 'connection-7', 'issuer' => self::ISSUER, 'subject' => 'subject-1'],
                self::requestContext(),
            );

            self::fail('An external result was taken as input.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Sign-in method [external_provider] is not registered.', $exception->getMessage());
        }

        self::assertSame([], $this->recorded);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * An exception from the link contract propagates, with nothing reported or
     * written.
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
            $this->sessions()->signInExternally(new ExternalResult('connection-7', self::ISSUER, 'subject-1'), self::requestContext());

            self::fail('The link contract\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame([], $this->recorded);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * Accepted evidence meets the identity-level factor requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAcceptedEvidenceMeetsTheIdentityLevelRequirement(): void
    {
        $identity = $this->seedIdentity();
        $evidence = new ExternalEvidence(['pwd', 'otp'], 'urn:example:acr:mfa', $this->now->addMinute());

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(multifactor: new RequirementPart));

        $pending = $this->sessions()->signInExternally($this->linkedResult($identity, evidence: $evidence), self::requestContext());

        self::assertTrue($pending->isPending());
        self::assertNull(SessionProvenance::query()->sole()->accepted_evidence);
        self::assertNull(SessionProof::query()->sole()->getAttributes()['evidence']);

        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR, RequirementKind::ADDITIONAL_VERIFICATION]));

        $session = $this->sessions()->signInExternally($this->linkedResult($identity, evidence: $evidence), self::requestContext())->session;

        self::assertNotNull($session);

        $proof      = SessionProof::query()->where('session_id', $session->record->getKey())->sole();
        $provenance = SessionProofs::provenance($session->record);
        $claims     = Auth::manager()->jwt('api')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertSame([true, true], [$proof->accepted, $proof->multifactor]);
        self::assertSame($this->now->getTimestamp(), $provenance?->evidence?->authenticatedAt->getTimestamp());
        self::assertSame(['pwd', 'otp'], $provenance->evidence->methods);
        self::assertIsArray($claims);
        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD, 'mfa'], $claims['amr'] ?? null);
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
            $this->sessions()->signInExternally($result, self::requestContext());

            self::fail('A misconfigured transport was let through.');
        } catch (\InvalidArgumentException) {
            self::assertSame([], $this->externalLinks()->asked);
        }

        self::assertSame(0, SessionProof::query()->count());
    }

    /**
     * Accepted evidence meets a tenant's factor requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAcceptedEvidenceMeetsATenantsFactorRequirement(): void
    {
        [$member, $membership] = $this->seedMember();

        $evidence = new ExternalEvidence(['otp'], null, $this->now);
        $policy   = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v3', new Requirement(new RequirementPart), ['connection-7']));

        $this->app?->instance(TenantAuthenticationPolicy::class, $policy);
        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::ADDITIONAL_VERIFICATION]));

        $met = $this->sessions('members')->signInExternally($this->linkedResult($member, evidence: $evidence), self::asPrincipal($membership));

        self::assertTrue($met->isSignedIn());
        self::assertSame('v3', $met->session?->record->getTenantPolicyVersion());

        $elsewhere = $this->sessions('members')->signInExternally($this->linkedResult($member, 'connection-8', evidence: $evidence), self::asPrincipal($membership));

        self::assertSame(FailureReason::SSO_REQUIRED, $elsewhere->reason);
    }

    /**
     * Evidence that only meets phishing resistance meets a tenant that requires
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceMeetingOnlyPhishingResistanceMeetsATenantThatRequiresIt(): void
    {
        [$member, $membership] = $this->seedMember();

        $evidence = new ExternalEvidence(['hwk'], null, $this->now);
        $policy   = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v4', new Requirement(phishingResistance: new RequirementPart)));

        $this->app?->instance(TenantAuthenticationPolicy::class, $policy);
        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::PHISHING_RESISTANCE]));

        $met = $this->sessions('members')->signInExternally($this->linkedResult($member, evidence: $evidence), self::asPrincipal($membership));

        self::assertTrue($met->isSignedIn());
        self::assertSame([true, false], [SessionProof::query()->sole()->accepted, SessionProof::query()->sole()->multifactor]);
        self::assertNotNull(SessionProof::query()->sole()->evidence);
    }

    /**
     * A result naming its link signs in only through that link.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResultNamingItsLinkSignsInOnlyThroughThatLink(): void
    {
        $identity = $this->seedIdentity();
        $linked   = $this->linkedResult($identity, linkId: 'link-2');
        $policy   = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]);
        $named    = fn (string $linkId): ExternalResult => new ExternalResult(
            $linked->connectionId,
            $linked->issuer,
            $linked->subject,
            evidence: new ExternalEvidence(['mfa'], null, $this->now),
            linkId: $linkId,
        );

        $this->app?->instance(ExternalEvidencePolicy::class, $policy);

        $this->recordEvents([AuthenticationFailed::class]);

        $refused = $this->sessions()->signInExternally($named('link-1'), self::requestContext());

        self::assertSame(FailureReason::LINK_MISMATCH, $refused->reason);
        $failures = $this->recordedAs(AuthenticationFailed::class);

        self::assertSame([FailureReason::LINK_MISMATCH], array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $failures));
        self::assertSame([], $policy->asked);
        self::assertSame(0, Session::query()->count());

        $levels = [];

        $this->externalLinks()->whileAsked(static function () use (&$levels): void {
            $levels[] = DB::transactionLevel();
        });

        $signedIn = $this->sessions()->signInExternally($named('link-2'), self::requestContext());

        self::assertTrue($signedIn->isSignedIn());
        self::assertSame([1], $levels);
        self::assertSame('link-2', $signedIn->session === null ? null : SessionProofs::provenance($signedIn->session->record)?->linkId);
    }

    /**
     * Evidence accepted only for a level meets a tenant that requires a level.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceAcceptedOnlyForALevelMeetsATenantThatRequiresALevel(): void
    {
        [$member, $membership] = $this->seedMember();

        $evidence = new ExternalEvidence(['pwd'], 'urn:example:acr:silver', $this->now);
        $required = new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL2));
        $trusting = new ScriptedEvidencePolicy([RequirementKind::MINIMUM_LEVEL]);

        $this->app?->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v4', $required)));
        $this->app?->instance(ExternalEvidencePolicy::class, $trusting);

        $met    = $this->sessions('members')->signInExternally($this->linkedResult($member, evidence: $evidence), self::asPrincipal($membership));
        $judged = array_values(array_filter($trusting->asked, static fn (array $asked): bool => !$asked['accepting']));

        self::assertTrue($met->isSignedIn());
        self::assertSame([true, false], [SessionProof::query()->sole()->accepted, SessionProof::query()->sole()->multifactor]);
        self::assertSame($required, $judged[0]['requirement'] ?? null);
    }

    /**
     * Without a context the request's client is used.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAContextTheRequestsClientIsUsed(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, sessionNotAfter: $this->now->addHours(2));
        $session  = $this->sessions()->signInExternally($result, self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame(self::CLIENT_IP, $session->record->getAttribute($session->record->getCreatedIpName()));
        self::assertSame($this->now->addHours(2)->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * A cookie application's external sign-in is exempt from the same-site
     * check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsExternalSignInIsExemptFromTheSameSiteCheck(): void
    {
        config()->set('auth.guards.api.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        request()->headers->set('Origin', 'https://provider.example.test');
        request()->headers->remove('X-Requested-With');

        foreach ([self::requestContext(), new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT))] as $context) {

            $session = $sessions->signInExternally($this->linkedResult($identity), $context)->session;

            self::assertNotNull($session);
            self::assertNull($session->tokens->refreshToken);
            self::assertNotNull($session->tokens->refreshCookie);
        }
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
