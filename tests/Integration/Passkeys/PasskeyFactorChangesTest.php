<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\RecordingPasskeyFactorGate;
use Tests\TestCase;

/**
 * Proves, on whichever engine the suite runs against, that the factor gate's
 * work and the passkey's row are one change inside a transaction of the
 * caller's: a caller that rolls back keeps neither the passkey nor what the
 * gate wrote (here its own record of the factor), and reports nothing; one that
 * commits keeps both, and reports once. A gate that requires the storage
 * connection's transaction finds it open on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyService::class)]
final class PasskeyFactorChangesTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var string Table the gate records the factors it associates in. */
    private const string FACTORS = 'gate_factors';

    /**
     * Freeze the clock, create the tables, and bind a gate that records each
     * factor it associates, and forgets it on a removal, in its own table on
     * the storage connection.
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

        $this->createSessionTables();

        Schema::create(self::FACTORS, static function (Blueprint $blueprint): void {
            $blueprint->string('credential_id', 512);
        });

        app()->instance(PasskeyFactorGate::class, new RecordingPasskeyFactorGate(
            static function (RegisteredPasskey $passkey): PasskeyFactorAssociation {
                DB::table(self::FACTORS)->insert(['credential_id' => $passkey->credentialId]);

                return new PasskeyFactorAssociation('factor-1');
            },
            static function (string $passkeyId, string $credentialId): void {
                DB::table(self::FACTORS)->where('credential_id', $credentialId)->delete();
            },
        ));
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::FACTORS);

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A registration inside the caller's transaction commits or rolls back with
     * it, the factor the gate recorded included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationAndItsFactorFollowTheCallersTransaction(): void
    {
        $identity = $this->seedIdentity();
        $passkeys = Auth::passkeys('api');

        Event::fake([PasskeyAdded::class]);

        DB::beginTransaction();

        $options = $passkeys->registrationOptions($identity, self::USER_NAME);

        self::assertSame('factor-1', $passkeys->register($identity, $options->challengeId, $this->authenticator()->create($options->options))->factor?->factor);

        DB::rollBack();

        self::assertSame([0, 0], [Passkey::query()->count(), DB::table(self::FACTORS)->count()]);

        Event::assertNotDispatched(PasskeyAdded::class);

        $registered = DB::transaction(function () use ($passkeys, $identity): bool {
            $options = $passkeys->registrationOptions($identity, self::USER_NAME);

            return $passkeys->register($identity, $options->challengeId, $this->authenticator()->create($options->options))->isRegistered();
        });

        self::assertTrue($registered);
        self::assertSame([1, 1], [Passkey::query()->count(), DB::table(self::FACTORS)->count()]);
        self::assertSame(Passkey::query()->sole()->credential_id, DB::table(self::FACTORS)->value('credential_id'));

        Event::assertDispatchedTimes(PasskeyAdded::class, 1);
    }

    /**
     * A removal inside the caller's transaction commits or rolls back with it,
     * the factor the gate forgot included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalAndItsFactorFollowTheCallersTransaction(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);
        $passkeys = Auth::passkeys('api');

        Event::fake([PasskeyRemoved::class]);

        DB::beginTransaction();

        self::assertTrue($passkeys->remove($identity, $passkey->id));

        DB::rollBack();

        self::assertSame([1, 1], [Passkey::query()->count(), DB::table(self::FACTORS)->count()]);

        Event::assertNotDispatched(PasskeyRemoved::class);

        self::assertTrue(DB::transaction(static fn (): bool => $passkeys->remove($identity, $passkey->id)));
        self::assertSame([0, 0], [Passkey::query()->count(), DB::table(self::FACTORS)->count()]);

        Event::assertDispatchedTimes(PasskeyRemoved::class, 1);
    }

    /**
     * Configure the guards and their relying party.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }
}
