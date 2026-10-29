<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Integration test of one listener registered for the `AuthenticationEvent`
 * contract over the session lifecycle against a real database: a switch of
 * principal, a sign-out everywhere, a sign-out, a principal choice, a further
 * factor and a verified identifier each reach it, and each event's context
 * names the guard, the identity and the principal it concerns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdditionalFactorRequired::class)]
#[CoversClass(DeviceRevoked::class)]
#[CoversClass(IdentifierVerified::class)]
#[CoversClass(PrincipalChoiceRequired::class)]
#[CoversClass(PrincipalSwitched::class)]
#[CoversClass(SignedOutEverywhere::class)]
final class LifecycleEventsContractTest extends TestCase
{
    use InteractsWithSessions, InteractsWithVerifiableIdentities;

    /** @var list<class-string> The lifecycle events the listener's record is checked for. */
    private const array LIFECYCLE = [
        AdditionalFactorRequired::class,
        DeviceRevoked::class,
        IdentifierVerified::class,
        PrincipalChoiceRequired::class,
        PrincipalSwitched::class,
        SignedOutEverywhere::class,
    ];

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

        self::createVerifiableIdentitiesTable();
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('verifiable_identities');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Each lifecycle event reaches the one contract listener once, in the order
     * it happened, and its context names what it concerns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneListenerOnTheContractReceivesEveryLifecycleEvent(): void
    {
        [$member] = $this->seedMember();

        $tenant = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        /** @var list<array{0: string, 1: string, 2: ?string, 3: ?string}> $captured */
        $captured = [];

        Event::listen(AuthenticationEvent::class, static function (AuthenticationEvent $event) use (&$captured): void {
            if (!in_array($event::class, self::LIFECYCLE, true)) {
                return;
            }

            $captured[] = [class_basename($event), $event->context()->guard, $event->context()->identityId, $event->context()->principalId];
        });

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);
        self::assertTrue($this->sessions('members')->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());

        $guard = $this->freshGuard('members');

        $guard->login($member, $second, $session->device);

        self::assertSame(0, $guard->sessions()->signOutEverywhere(true));
        self::assertTrue($guard->sessions()->signOut());

        $chooser = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $choosable = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $chooser->getKey(), 'tenant_id' => $choosable->getKey()]);
        }

        self::assertTrue($this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'))->requiresPrincipal());

        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });

        self::assertNotNull($this->sessions()->signIn('password', self::credentials())->pending);

        $verifiable = self::seedVerifiableIdentity();

        self::assertSame(IdentifierVerification::VERIFIED, app(IdentifierVerifier::class)->verify('api', $verifiable, 'email', 'ben@example.com'));

        $memberId   = IdentifierCoercion::stringify($member->getKey());
        $secondId   = IdentifierCoercion::stringify($second->getKey());
        $identityId = IdentifierCoercion::stringify($identity->getKey());

        self::assertSame([
            ['PrincipalSwitched', 'members', $memberId, $secondId],
            ['SignedOutEverywhere', 'members', $memberId, null],
            ['DeviceRevoked', 'members', $memberId, $secondId],
            ['PrincipalChoiceRequired', 'choosers', IdentifierCoercion::stringify($chooser->getKey()), null],
            ['AdditionalFactorRequired', 'api', $identityId, $identityId],
            ['IdentifierVerified', 'api', IdentifierCoercion::stringify($verifiable->getKey()), null],
        ], $captured);
    }

    /**
     * Register the guards, and a guard over the choosing members.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
    }
}
