<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Query-budget contracts for identifier verification and the sign-in gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierVerifier::class)]
#[CoversClass(VerificationLinks::class)]
#[CoversClass(GuardAudiencePolicy::class)]
final class IdentifierVerificationQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithVerifiableIdentities;

    /** @var string Guard the verifications are made for. */
    private const string GUARD = 'verified_api';

    /**
     * Create the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createVerifiableIdentitiesTable();
    }

    /**
     * Drop the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('verifiable_identities');

        parent::tearDown();
    }

    /**
     * A verification is one locked read and one write; a repeat reads the row
     * under the lock, writes nothing, and adds the re-read that tells it from a
     * mismatch; a mismatch with the identifier in hand costs nothing.
     *
     * @return void
     */
    public function testVerificationIsOneLockedReadAndOneWrite(): void
    {
        $identity = self::seedVerifiableIdentity();
        $verifier = app(IdentifierVerifier::class);

        $verify = static fn (string $identifier): \Closure => static fn (): mixed => $verifier->verify(self::GUARD, $identity, 'email', $identifier);

        self::assertSame(IdentifierVerification::VERIFIED, $this->assertQueryBudget(1, 1, $verify('ben@example.com')));
        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, $this->assertQueryBudget(2, 0, $verify('ben@example.com')));
        self::assertSame(IdentifierVerification::MISMATCH, $this->assertQueryBudget(0, 0, $verify('eve@example.com')));
    }

    /**
     * Following a link loads the identity, reads its row again under the
     * verification's lock and writes once; a link with a bad signature costs
     * nothing.
     *
     * @return void
     */
    public function testFollowingALinkIsTwoReadsAndOneWrite(): void
    {
        $identity = self::seedVerifiableIdentity();
        $links    = app(VerificationLinks::class);
        $link     = $links->create(self::GUARD, $identity, 'email', 'verify');

        self::assertSame(IdentifierVerification::VERIFIED, $this->assertQueryBudget(2, 1, static fn (): mixed => $links->consume(Request::create($link))));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): mixed => $links->consume(Request::create($link . 'x'))));
    }

    /**
     * The sign-in gate reads the identity's loaded verification without a
     * query.
     *
     * @return void
     */
    public function testGateCostsNoQuery(): void
    {
        $identity = self::seedVerifiableIdentity();

        $identity->markIdentifierAsVerified('email', 'ben@example.com');

        self::assertNull($this->assertQueryBudget(0, 0, static fn (): mixed => app(AudiencePolicy::class)->admit(self::GUARD, $identity, new PlainPrincipalFixture(1), 'email')));
    }

    /**
     * Configure the guard and the route links point at.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'verifiable', 'audience' => ['require_verified_identifier' => true]]);
        $config->set('auth.providers.verifiable', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
    }

    /**
     * Define the route verification links point at.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get('/verify', static fn (): string => 'ok')->name('verify');
    }
}
