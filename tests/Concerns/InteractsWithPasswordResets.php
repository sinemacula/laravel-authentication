<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\LookAlikeModelProvider;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\Integration\Fixtures\PasswordMachine;

/**
 * Shared set-up for the password reset tests, built on the password helpers': a
 * frozen clock, the `password_identities` table, the guards (and a `lookalike`
 * one whose provider finds an email by any casing and accents, as a lenient
 * collation would), faked link and code senders, and the reset routes an
 * application would register (`/password/forgot`, `/password/forgot/code`,
 * `/password/reset`, `/password/reset/code`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithPasswordResets
{
    use InteractsWithPasswords;

    /** @var string The seeded identity's email address. */
    protected const string EMAIL = 'ada@example.test';

    /** @var string The seeded identity's phone number. */
    protected const string PHONE = '+447700900123';

    /** @var string The new password every reset sets. */
    protected const string NEW_PASSWORD = 'a brand new passphrase';

    /** @var string The frozen time every request starts at. */
    protected const string NOW = '2026-10-29 09:30:00';

    /** @var \SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender The link sender. */
    protected FakePasswordResetLinkSender $links;

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The code sender. */
    protected FakeOneTimeCodeSender $codes;

    /**
     * Freeze the clock, create the tables, fake the senders, register the
     * look-alike provider and the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeClock(CarbonImmutable::parse(self::NOW));
        self::createPasswordTables();

        $this->links = FakePasswordResetLinkSender::fake($this->app);
        $this->codes = FakeOneTimeCodeSender::fake($this->app);

        Auth::provider(
            'look-alike-plain',
            static fn (Application $app): LookAlikeModelProvider => new LookAlikeModelProvider($app->make(Hasher::class), IntegrationIdentity::class),
        );

        Auth::provider(
            'look-alike-passwords',
            static fn (Application $app): LookAlikeModelProvider => new LookAlikeModelProvider($app->make(Hasher::class), PasswordIdentity::class),
        );

        Route::post('/password/forgot', static fn (Request $request): array => ['status' => Auth::passwords('web')->sendResetLink($request->all())->status->value]);
        Route::post('/password/forgot/code', static fn (Request $request): array => ['status' => Auth::passwords('web')->sendResetCode('phone', $request->all())->status->value]);
        Route::post('/password/reset', static fn (Request $request): array => self::answer(Auth::passwords('web')->reset($request->all())));
        Route::post('/password/reset/code', static fn (Request $request): array => self::answer(Auth::passwords('web')->resetWithCode('phone', $request->all())));
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();
        self::freezeClock(null);

        parent::tearDown();
    }

    /**
     * Configure the guards, and one whose provider finds an email by any
     * casing, as a case-insensitive collation would.
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

        self::configurePasswordGuards($config);

        $config->set('auth.providers.lookalike', ['driver' => 'look-alike-passwords']);
        $config->set('auth.providers.plain_identities', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('auth.providers.lookalike_plain', ['driver' => 'look-alike-plain']);
        $config->set('auth.guards.lookalike_plain', ['driver' => 'jwt', 'provider' => 'lookalike_plain', 'audience' => ['methods' => ['password']]]);
        $config->set('auth.guards.plain', ['driver' => 'jwt', 'provider' => 'plain_identities', 'audience' => ['methods' => ['password']]]);
        $config->set('auth.guards.plain_verified', [
            'driver'   => 'jwt',
            'provider' => 'plain_identities',
            'audience' => ['methods' => ['password'], 'require_verified_identifier' => true],
        ]);
        $config->set('auth.guards.lookalike', ['driver' => 'jwt', 'provider' => 'lookalike', 'audience' => ['methods' => ['password']]]);
    }

    /**
     * The service of the guard, on a guard resolved for a fresh request.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     */
    protected function passwords(string $guard = 'web'): PasswordService
    {
        $this->freshGuard($guard);

        return Auth::passwords($guard);
    }

    /**
     * Request a link for the seeded identity, deliver it, and return its token.
     *
     * @return string
     *
     * @throws \Throwable
     */
    protected function requestLink(): string
    {
        self::assertTrue($this->passwords()->sendResetLink(['email' => self::EMAIL])->isSent());

        app()->terminate();

        $token = $this->links->lastTokenFor(self::EMAIL);

        self::assertIsString($token);

        return $token;
    }

    /**
     * Issue a reset link token for the seeded email on the guard, directly.
     *
     * @param  string  $guard
     * @return string
     *
     * @throws \Throwable
     */
    protected static function issueToken(string $guard): string
    {
        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink($guard, 'email', self::EMAIL), CarbonImmutable::now(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued->code;
    }

    /**
     * Persist the identity resets are for: verified email and phone number.
     *
     * @param  array<string, mixed>  $attributes
     * @return \Tests\Integration\Fixtures\PasswordIdentity
     */
    protected static function seedResettable(array $attributes = []): PasswordIdentity
    {
        return self::seedPasswordIdentity(self::EMAIL, ['phone' => self::PHONE, 'phone_verified_at' => '2026-01-01 00:00:00', ...$attributes]);
    }

    /**
     * Persist a machine identity holding the email, verified, and a password.
     *
     * @return \Tests\Integration\Fixtures\PasswordMachine
     */
    protected static function seedMachine(): PasswordMachine
    {
        $machine = new PasswordMachine;

        $machine->forceFill(['email' => self::EMAIL, 'email_verified_at' => '2026-01-01 00:00:00', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        return $machine;
    }

    /**
     * What a reset route answers.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\ResetResult  $result
     * @return array{status: string, revoked: int, violations: list<string>}
     */
    protected static function answer(ResetResult $result): array
    {
        return [
            'status'     => $result->status->value,
            'revoked'    => $result->revoked,
            'violations' => array_map(static fn (PasswordViolation $violation): string => $violation->value, $result->violations),
        ];
    }
}
