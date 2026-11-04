<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\SessionTokens;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Feature tests, through the `Auth` facade and the session service, of the
 * expiry every token pair carries: a sign-in, a pending session satisfied, a
 * choice, a refresh and its grace retry, a switch, and a cookie application's
 * sign-in each hand back a pair that says its access token expires when the
 * token's own `exp` says, and lives the seconds from its `iat` to then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenPair::class)]
#[CoversClass(SessionTokens::class)]
final class TokenPairTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose identities hold several principals. */
    private const string CHOOSERS = 'choosers';

    /** @var string Guard whose refresh token travels in a cookie. */
    private const string BROWSER = 'browser';

    /** @var int The access lifetime the tests configure, in seconds. */
    private const int ACCESS_LIFETIME = 15 * 60;

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

        $this->clockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
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
     * A sign-in's pair, a body application's and a cookie application's, says
     * when its access token expires.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsPairSaysWhenItsAccessTokenExpires(): void
    {
        $this->seedIdentity();

        foreach (['api', self::BROWSER] as $guard) {

            $tokens = $this->sessions($guard)->signIn('password', self::credentials())->session?->tokens;

            self::assertNotNull($tokens);
            self::assertSame($guard === self::BROWSER, $tokens->refreshCookie !== null);

            $this->assertExpiresAsItsAccessTokenDoes($guard, $tokens);
        }
    }

    /**
     * The pair a pending session is activated with, by its factor or by a
     * choice, says when its access token expires, from the activation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivatedPendingSessionsPairSaysWhenItsAccessTokenExpires(): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($pending->pending);

        $this->clockAt($this->now->addMinute());

        $satisfied = $this->sessions()->satisfy($pending->credential?->reveal() ?? '', self::adapterProof($identity, 'api', $pending->pending->id, Purpose::SIGN_IN));

        self::assertNotNull($satisfied->session);

        $this->assertExpiresAsItsAccessTokenDoes('api', $satisfied->session->tokens);

        app()->forgetInstance(AdditionalFactorPolicy::class);

        [$chooser, $first] = $this->seedChooser();

        $choice = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials($chooser->email));

        $this->clockAt($this->now->addMinute());

        $chosen = $this->sessions(self::CHOOSERS)->choose($choice->credential?->reveal() ?? '', $first);

        self::assertNotNull($chosen->session);

        $this->assertExpiresAsItsAccessTokenDoes(self::CHOOSERS, $chosen->session->tokens);
    }

    /**
     * A refresh's pair, and the pair a retry of it within the grace window is
     * reissued, says when its access token expires, from the refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshsPairAndItsRetrysSayWhenTheirAccessTokensExpire(): void
    {
        $this->seedIdentity();

        $token = $this->sessions()->signIn('password', self::credentials())->session?->tokens->refreshToken?->reveal() ?? '';

        $this->clockAt($this->now->addMinutes(2));

        foreach ([$this->sessions()->refresh($token), $this->sessions()->refresh($token)] as $refreshed) {

            self::assertTrue($refreshed->isRefreshed());
            self::assertNotNull($refreshed->session);

            $this->assertExpiresAsItsAccessTokenDoes('api', $refreshed->session->tokens);
        }
    }

    /**
     * A switch's pair says when its access token expires, from the switch.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchsPairSaysWhenItsAccessTokenExpires(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $signIn = SignInContext::fromRequest(request(), principal: $first);
        $token  = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $signIn)->session?->tokens->refreshToken?->reveal() ?? '';

        $this->clockAt($this->now->addMinutes(3));

        $switched = $this->sessions('members')->switchTo($token, SwitchTarget::principal($second));

        self::assertTrue($switched->isSwitched());
        self::assertNotNull($switched->session);

        $this->assertExpiresAsItsAccessTokenDoes('members', $switched->session->tokens);
    }

    /**
     * Register the session guards, the choosers' guard and a cookie
     * application.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password']]]);
        $config->set('auth.guards.' . self::BROWSER, [
            'driver'        => 'jwt',
            'provider'      => 'identities',
            'application'   => ['methods' => ['password']],
            'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/']],
        ]);
    }

    /**
     * Assert the pair says its access token expires at the token's `exp`, now
     * plus the default access lifetime, and lives that lifetime: `exp` minus
     * `iat`.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @return void
     */
    private function assertExpiresAsItsAccessTokenDoes(string $guard, TokenPair $tokens): void
    {
        $claims = Auth::jwt($guard)->parse($tokens->accessToken, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertIsInt($claims['exp']);
        self::assertIsInt($claims['iat']);
        self::assertSame([$claims['exp'], $claims['exp'] - $claims['iat']], [$tokens->expiresAt->getTimestamp(), $tokens->expiresIn]);
        self::assertSame([$this->now->getTimestamp() + self::ACCESS_LIFETIME, self::ACCESS_LIFETIME], [$tokens->expiresAt->getTimestamp(), $tokens->expiresIn]);
    }

    /**
     * A chooser with two memberships, each in an active tenant of its own.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$member, $memberships[0]];
    }

    /**
     * Set every clock to the time.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        $this->now = $at;

        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
