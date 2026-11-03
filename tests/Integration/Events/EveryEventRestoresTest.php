<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Integration test that every package event, whatever it carries beside its
 * context, survives a queue whose wait outlived the rows it names: it holds no
 * model, so it restores as the same event with no query, every value of its
 * context (when it happened, who, as whom, within which tenant, on which
 * session, how, from where, through which connection and for which request) and
 * its own values as they were.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EveryEventRestoresTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::parse('2026-04-06 12:00:00.250000', 'UTC');

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
     * Rows of `[event class, arguments after the context]`: every event the
     * package dispatches, with values for what it carries beside its context.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>, 1: list<mixed>}>
     */
    public static function provideEvents(): iterable
    {
        $at = CarbonImmutable::parse('2026-04-06 12:05:00', 'UTC');

        yield from [
            'ApiKeyIssued'              => [ApiKeyIssued::class, []],
            'ApiKeyRevoked'             => [ApiKeyRevoked::class, []],
            'ApiKeyRotated'             => [ApiKeyRotated::class, ['key-0']],
            'AuthenticationFailed'      => [AuthenticationFailed::class, [AuthenticationFlow::SIGN_IN, FailureReason::RATE_LIMITED, 'member@example.test', 30, 'challenge-1']],
            'ClientCredentialsGranted'  => [ClientCredentialsGranted::class, []],
            'ExternalResultRedeemed'    => [ExternalResultRedeemed::class, [AuthenticationFlow::SIGN_IN]],
            'ExternalResultUnlinked'    => [ExternalResultUnlinked::class, ['https://idp.example.test']],
            'IdentifierChangeRequested' => [IdentifierChangeRequested::class, ['email', 'new@example.test', $at]],
            'IdentifierChanged'         => [IdentifierChanged::class, ['email', 'old@example.test', 'new@example.test', $at]],
            'IdentifierVerified'        => [IdentifierVerified::class, ['email']],
            'PasskeyAdded'              => [PasskeyAdded::class, []],
            'PasskeyRemoved'            => [PasskeyRemoved::class, []],
            'PasskeyUsed'               => [PasskeyUsed::class, []],
            'PasswordSet'               => [PasswordSet::class, [PasswordFlow::CHANGE]],
            'PrincipalAssigned'         => [PrincipalAssigned::class, []],
            'PrincipalSwitched'         => [PrincipalSwitched::class, ['membership', '9', 't-9', true, true]],
            'Reauthenticated'           => [Reauthenticated::class, []],
            'Refreshed'                 => [Refreshed::class, []],
            'SessionActivated'          => [SessionActivated::class, []],
            'SessionAuthenticated'      => [SessionAuthenticated::class, []],
            'SessionCreated'            => [SessionCreated::class, []],
            'SessionPending'            => [SessionPending::class, [['mfa', 'principal'], $at]],
            'SessionReturnedToPending'  => [SessionReturnedToPending::class, [['mfa'], $at, AuthenticationFlow::REFRESH, 'membership', '9', '4']],
            'SessionRevoked'            => [SessionRevoked::class, [RevocationReason::SIGNED_OUT]],
            'SignedIn'                  => [SignedIn::class, [true, false]],
            'SignedOutEverywhere'       => [SignedOutEverywhere::class, [RevocationReason::SIGNED_OUT_EVERYWHERE, 3, $at]],
            'SteppedUp'                 => [SteppedUp::class, [ProofKind::RECOVERY_CODE]],
        ];
    }

    /**
     * The event restores, after every row it names was deleted, as the same
     * event, with no query, every value of its context unchanged, and its own
     * values as they were; its payload names no model.
     *
     * @param  class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>  $class
     * @param  list<mixed>  $arguments
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEvents')]
    public function testTheEventRestoresWithItsSnapshotOnceItsRowsAreGone(string $class, array $arguments): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $client  = new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
        $context = new EventContext(
            'members',
            $client,
            $member,
            $membership,
            $tenant,
            $session->record,
            'password',
            credentialId: 'key-1',
            scopes: ['read'],
            connectionId: 'connection-7',
            requestReference: 'request-3',
        );
        $event  = new $class($context, ...$arguments);
        $queued = serialize($event);

        Session::query()->delete();
        ActivatableTenantMembership::query()->delete();
        ActivatableTenantMember::query()->delete();
        ActivatableTenant::query()->forceDelete();

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $copy = unserialize($queued);

        self::assertInstanceOf($class, $copy);
        self::assertSame(0, $queries);
        self::assertStringNotContainsString('ModelIdentifier', $queued);

        $restored = $copy->context();

        self::assertEquals($context, $restored);
        self::assertSame($context->toArray(), $restored->toArray());
        self::assertSame('2026-04-06T12:00:00.250000Z', $restored->toArray()['occurred_at']);
        self::assertSame($member->getMorphClass(), $restored->identityType);
        self::assertSame($membership->getMorphClass(), $restored->principalType);
        self::assertSame($tenant->getMorphClass(), $restored->tenantType);
        self::assertSame($session->record->getKey(), $restored->sessionId);
        self::assertEquals(self::ownValues($event), self::ownValues($copy));
    }

    /**
     * The events above are every event the package dispatches, so a new event
     * is held to the same queue contract.
     *
     * @return void
     */
    public function testEveryPackageEventIsChecked(): void
    {
        $events = [];

        foreach (glob(dirname(__DIR__, 3) . '/src/Events/*.php') ?: [] as $file) {

            $class = 'SineMacula\Laravel\Authentication\Events\\' . basename($file, '.php');

            if (!is_a($class, AuthenticationEvent::class, true) || (new \ReflectionClass($class))->isAbstract()) {
                continue;
            }

            $events[] = basename($file, '.php');
        }

        self::assertSame($events, array_keys(iterator_to_array(self::provideEvents())));
    }

    /**
     * Configure the guards.
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
     * The event's own values beside its context.
     *
     * @param  object  $event
     * @return array<string, mixed>
     */
    private static function ownValues(object $event): array
    {
        return array_diff_key(get_object_vars($event), ['context' => true]);
    }
}
