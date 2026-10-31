<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoices;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * End-to-end test of a principal choice over HTTP against a real database: a
 * sign-in offers the choice, the choice lists the principals, choosing one
 * starts the session as it, and the access token it issues authenticates a
 * request through the `auth` middleware as the chosen principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(PrincipalChoices::class)]
final class PrincipalChoiceEndToEndTest extends TestCase
{
    use InteractsWithRateLimits, InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, which has no default principal. */
    private const string GUARD = 'choosers';

    /** @var string Email of the member that chooses. */
    private const string CHOOSER = 'chooser@example.test';

    /**
     * Freeze the clocks, create the tables and register the routes.
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

        Route::post('/sign-in', static function (Request $request): array {

            $credentials = ['email' => $request->string('email')->toString(), 'password' => $request->string('password')->toString()];

            return ['choice' => Auth::sessions(self::GUARD)->signIn('password', $credentials)->choice?->token];
        });

        Route::post('/choose', static function (Request $request): array {

            $result = Auth::sessions(self::GUARD)->choose($request->string('choice')->toString(), ChoosingMembership::query()->findOrFail($request->integer('membership')));

            return ['status' => $result->status->value, 'access' => $result->session?->tokens->accessToken];
        });

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => [
            'principal' => Auth::principal()?->getPrincipalIdentifier(),
            'device'    => Auth::device()?->getDeviceIdentifier(),
        ]);
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
     * Offering, listing and making the choice: the chosen session records the
     * principal, the method and the identifier type of the sign-in, the choice
     * is used up and its attempt slots are given back, and its access token
     * authenticates a request as the chosen principal on that device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChosenSessionAuthenticatesABearerRequestAsTheChosenPrincipal(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $token = $this->postJson('/sign-in', ['email' => self::CHOOSER, 'password' => self::PASSWORD])->assertOk()->json('choice');

        self::assertIsString($token);
        self::assertSame([1, 1, 1], $this->hits($member));

        $choice = Auth::sessions(self::GUARD)->choice($token);

        self::assertNotNull($choice);
        self::assertSame([$first->getKey(), $second->getKey()], array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $choice->principals));

        $access = $this->postJson('/choose', ['choice' => $token, 'membership' => $second->getKey()])
            ->assertOk()
            ->assertJson(['status' => 'signed_in'])
            ->json('access');

        self::assertIsString($access);

        $device = Device::query()->sole();

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify($device->getAttribute('principal_id')));
        self::assertSame('password', $device->getAttribute('sign_in_method'));
        self::assertSame('email', $device->getAttribute('sign_in_identifier_type'));
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame([0, 0, 0], $this->hits($member));
        self::assertNull(Auth::sessions(self::GUARD)->choice($token));

        $this->withHeaders(['Authorization' => 'Bearer ' . $access])
            ->getJson('/me')
            ->assertOk()
            ->assertExactJson(['principal' => $second->getKey(), 'device' => $device->getKey()]);
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
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
    }

    /**
     * Persist a member with two memberships, each in its own active tenant.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership, 2: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member = ChoosingMember::query()->create(['email' => self::CHOOSER, 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $first  = ActivatableTenant::query()->create(['name' => 'First', 'is_active' => true]);
        $second = ActivatableTenant::query()->create(['name' => 'Second', 'is_active' => true]);

        return [
            $member,
            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $first->getKey()]),
            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $second->getKey()]),
        ];
    }

    /**
     * The hits on the chooser's identifier, the test client's IP address and
     * the account's sign-in counters.
     *
     * @param  \Tests\Integration\Fixtures\ChoosingMember  $member
     * @return list<int>
     */
    private function hits(ChoosingMember $member): array
    {
        return [
            self::counterHits(self::GUARD, 'sign_in', 'per_identifier', self::CHOOSER),
            self::counterHits(self::GUARD, 'sign_in', 'per_ip', '127.0.0.1'),
            self::counterHits('sign_in', 'per_account', AccountAttempts::account($member)),
        ];
    }
}
