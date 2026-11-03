<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\StubBareSession;

/**
 * Feature tests of what a contributor to the authentication context is given:
 * the bound instances as they are, and the session's external provenance, read
 * on the write connection the first time it is asked for and never again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContributionSubject::class)]
final class ContributionSubjectTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var int Reads of the provenance table since counting began. */
    private int $provenanceReads = 0;

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
     * A session an external provider established has its provenance read once,
     * on the first ask, as the session records it, the adapter's provider
     * context with it in the same read; asked again it is the same provenance,
     * read from nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalSessionsProvenanceIsReadOnceOnTheFirstAsk(): void
    {
        $identity = $this->seedIdentity();
        $context  = new ProviderContext(['protocol' => 'saml', 'link' => ['made' => 'explicitly']]);
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity, 'connection-7', 'link-9', tenantId: 'tenant-3', providerContext: $context))->session;

        self::assertNotNull($session);

        $subject = self::subject($identity, $session->record);

        $this->countProvenanceReads();

        self::assertSame(0, $this->provenanceReads);

        $provenance = $subject->provenance();

        self::assertNotNull($provenance);
        self::assertSame(['connection-7', 'tenant-3', 'link-9'], [$provenance->connectionId, $provenance->tenantId, $provenance->linkId]);
        self::assertSame(['protocol' => 'saml', 'link' => ['made' => 'explicitly']], $provenance->providerContext?->toArray());
        self::assertSame($provenance, $subject->provenance());
        self::assertSame(1, $this->provenanceReads);
    }

    /**
     * A session no external provider established has none, read once; without a
     * session, or with one that is not an Eloquent session (a plain session, or
     * an Eloquent model that is not one), there is none and nothing is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutProvenanceHasNone(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->countProvenanceReads();

        $password = self::subject($identity, $session->record);

        self::assertNull($password->provenance());
        self::assertNull($password->provenance());
        self::assertSame(1, $this->provenanceReads);

        self::assertNull(self::subject($identity, null)->provenance());
        self::assertNull(self::subject($identity, new PlainSessionFixture((string) IdentifierCoercion::stringify($session->record->getKey())))->provenance());
        self::assertNull(self::subject($identity, new StubBareSession(['id' => IdentifierCoercion::stringify($session->record->getKey())]))->provenance());
        self::assertSame(1, $this->provenanceReads);
    }

    /**
     * Register the guards and providers.
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
     * What a contributor is given for the identity acting as itself in the
     * session.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Context\ContributionSubject
     */
    private static function subject(IntegrationIdentity $identity, ?Session $session): ContributionSubject
    {
        $id      = IdentifierCoercion::stringify($identity->getKey());
        $context = new AuthenticationContext(SubjectType::PERSON, 'identity', $id, 'identity', $id, null, null, 'api', null, [], null, false, false, false, null, null, null, null);

        return new ContributionSubject($context, $identity, $identity, null, $session);
    }

    /**
     * Count the reads of the provenance table from now on.
     *
     * @return void
     */
    private function countProvenanceReads(): void
    {
        $this->provenanceReads = 0;

        DB::listen(function (QueryExecuted $query): void {

            if (!str_contains($query->sql, 'authentication_provenance')) {
                return;
            }

            $this->provenanceReads++;
        });
    }
}
