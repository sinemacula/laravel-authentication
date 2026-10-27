<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Proves that a password sign-in upgrades a stored hash the hasher no longer
 * produces (here a lower bcrypt cost) once the sign-in is admitted, honouring
 * Laravel's `hashing.rehash_on_login`, and that nothing else writes the
 * password: not a failed or refused sign-in, not `validate()`, and not a
 * request authenticated by a bearer token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordSignIn::class)]
#[CoversClass(AbstractGuard::class)]
final class PasswordRehashIntegrationTest extends TestCase
{
    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Email of the seeded identity. */
    private const string EMAIL = 'rehash@example.test';

    /** @var int Bcrypt cost the hasher is configured with. */
    private const int CURRENT_ROUNDS = 5;

    /** @var int Lower bcrypt cost the stored hash was made with. */
    private const int OUTDATED_ROUNDS = 4;

    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('integration_identities');

        parent::tearDown();
    }

    /**
     * A successful sign-in replaces an outdated hash with one at the current
     * cost, which still verifies the same password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInRehashesAnOutdatedPassword(): void
    {
        $identity = $this->seedIdentity();
        $outdated = $identity->password;

        self::assertTrue($this->guard()->attempt($this->credentials()));

        $stored = $this->storedHash($identity);

        self::assertNotSame($outdated, $stored);
        self::assertSame(self::CURRENT_ROUNDS, password_get_info($stored)['options']['cost'] ?? null);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, $stored));
    }

    /**
     * A hash already at the current cost is left as it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACurrentHashIsLeftAlone(): void
    {
        $identity = $this->seedIdentity(self::CURRENT_ROUNDS);
        $current  = $identity->password;

        self::assertTrue($this->guard()->attempt($this->credentials()));
        self::assertSame($current, $this->storedHash($identity));
    }

    /**
     * Laravel's `hashing.rehash_on_login` set to `false` turns the rehash off.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRehashOnLoginOffLeavesTheHash(): void
    {
        config()->set('hashing.rehash_on_login', false);

        $identity = $this->seedIdentity();
        $outdated = $identity->password;

        self::assertTrue($this->guard()->attempt($this->credentials()));
        self::assertSame($outdated, $this->storedHash($identity));
    }

    /**
     * Only an admitted sign-in rehashes: a wrong password, an identity that is
     * refused after its password was accepted, and `validate()` leave the hash
     * as it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingButAnAdmittedSignInRehashes(): void
    {
        $identity = $this->seedIdentity();
        $outdated = $identity->password;

        self::assertFalse($this->guard()->attempt(['email' => self::EMAIL, 'password' => 'wrong']));
        self::assertTrue($this->guard()->validate($this->credentials()));

        $identity->forceFill(['is_active' => false])->save();

        self::assertFalse($this->guard()->attempt($this->credentials()));
        self::assertSame($outdated, $this->storedHash($identity));
    }

    /**
     * A request authenticated by a bearer token never touches the password,
     * however outdated its hash.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestNeverRehashes(): void
    {
        $identity = $this->seedIdentity();
        $outdated = $identity->password;
        $token    = Auth::manager()->jwt('api')->issueAccessToken($identity, $identity, null);

        app()->instance('request', Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        Auth::forgetGuards();

        self::assertSame($identity->getKey(), Auth::guard('api')->user()?->getAuthIdentifier());
        self::assertSame($outdated, $this->storedHash($identity));
    }

    /**
     * Register the guard over the identity model, with the hasher at the
     * current cost.
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

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('hashing.driver', 'bcrypt');
        $config->set('hashing.bcrypt.rounds', self::CURRENT_ROUNDS);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist the identity with a hash made at the given cost.
     *
     * @param  int  $rounds
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private function seedIdentity(int $rounds = self::OUTDATED_ROUNDS): IntegrationIdentity
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = self::EMAIL;
        $identity->password  = app(Hasher::class)->make(self::PASSWORD, ['rounds' => $rounds]);
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * The identity's hash as the database now holds it.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return string
     */
    private function storedHash(IntegrationIdentity $identity): string
    {
        $hash = IntegrationIdentity::query()->whereKey($identity->getKey())->value('password');

        self::assertIsString($hash);

        return $hash;
    }

    /**
     * The identity's correct credentials.
     *
     * @return array<string, string>
     */
    private function credentials(): array
    {
        return ['email' => self::EMAIL, 'password' => self::PASSWORD];
    }

    /**
     * A fresh guard for a new request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function guard(): AbstractGuard
    {
        Auth::forgetGuards();

        $guard = Auth::guard('api');

        self::assertInstanceOf(AbstractGuard::class, $guard);

        return $guard;
    }
}
