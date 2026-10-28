<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubReplacementPrincipalResolver;

/**
 * Feature tests for `authentication:check`: it resolves each `jwt` guard's
 * settings and the device model as the package would, lists every problem it
 * finds as `[<guard>] <message>`, exits `1` when there is one and `0` when
 * there is none, and reads configuration only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    /** @var string A signing secret long enough for HS256. */
    private const string SECRET = 'a-signing-secret-of-at-least-32-bytes!!';

    /**
     * A configuration without problems passes, says so for each guard and the
     * device model, ignores guards of other drivers, and opens no database
     * connection.
     *
     * @return void
     */
    public function testAConfigurationWithoutProblemsPasses(): void
    {
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(['[device] OK', '[sign_in] OK', '[api] OK', '[admin] OK'], $output);
        self::assertSame(0, $queries);
    }

    /**
     * Rows of `[a change to the configuration, the problem it causes]`, one for
     * each check a guard runs.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideProblems(): iterable
    {
        yield 'a key too short for the algorithm' => [
            ['authentication.jwt.keys' => ['kid' => 'short']],
            '[api] JWT key \'kid\' is too short for HS256',
        ];
        yield 'a provider that is not an identity provider' => [
            ['auth.providers.users' => ['driver' => 'eloquent', 'model' => StubAuthenticatableModel::class]],
            '[api] Auth guard [api] provider must resolve to [SineMacula\Laravel\Authentication\Contracts\IdentityProvider]; got [Illuminate\Auth\EloquentUserProvider].',
        ];
        yield 'a provider that is not configured' => [
            ['auth.guards.api.provider' => 'missing'],
            '[api] Auth guard [api] provider must resolve to [SineMacula\Laravel\Authentication\Contracts\IdentityProvider]; got [null].',
        ];
        yield 'a principal resolver that is not one' => [
            ['auth.guards.api.principal_resolver' => \stdClass::class],
            '[api] Auth guard [api] principal_resolver [stdClass] resolved to [stdClass]',
        ];
        yield 'a malformed audience' => [
            ['auth.guards.api.audience' => ['methods' => []]],
            '[api] Audience `methods` for guard [api] must be a non-empty list',
        ];
        yield 'a malformed rate limit' => [
            ['auth.guards.api.rate_limits' => ['refresh' => ['per_ip' => ['max' => 0, 'decay_seconds' => 60]]]],
            '[api] Rate limit `refresh.per_ip` for guard [api] must be null or',
        ];
        yield 'a malformed password identifier' => [
            ['auth.guards.api.sign_in' => ['password_identifier' => 'Email']],
            '[api] auth.guards.api.sign_in.password_identifier must name the identifier column',
        ];
        yield 'a malformed refresh token transport' => [
            ['auth.guards.api.refresh_token' => ['sources' => ['cookie']]],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.path` must be the path of the refresh route',
        ];
        yield 'a device model that is not one' => [
            ['authentication.device.model' => \stdClass::class],
            '[device] authentication.device.model must be a non-empty class-string of an Eloquent model',
        ];
        yield 'a pruning retention out of range' => [
            ['authentication.device.prune_after_days' => 3651],
            '[device] `authentication.device.prune_after_days` must be an integer from 0 to 3650 days.',
        ];
        yield 'a pending sign-in lifetime out of range' => [
            ['authentication.sign_in.pending_ttl_seconds' => 5],
            '[sign_in] authentication.sign_in.pending_ttl_seconds must be an integer from 30 to 3600 seconds.',
        ];
    }

    /**
     * Each problem is listed with what it concerns, and the command fails.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideProblems')]
    public function testEachProblemIsListed(array $changes, string $problem): void
    {
        config()->set($changes);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertNotEmpty(array_filter($output, static fn (string $line): bool => str_starts_with($line, $problem)), implode("\n", $output));
    }

    /**
     * Every check runs, so one run lists every problem of every guard, and a
     * guard with none is still said to be OK.
     *
     * @return void
     */
    public function testEveryProblemIsListedInOneRun(): void
    {
        config()->set([
            'auth.guards.api.audience'                   => ['methods' => []],
            'auth.guards.api.refresh_token'              => ['header' => ''],
            'authentication.device.model'                => '',
            'authentication.device.prune_after_days'     => -1,
            'authentication.sign_in.pending_ttl_seconds' => 'soon',
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[admin] OK', $output);
        self::assertCount(4, array_filter($output, static fn (string $line): bool => str_starts_with($line, '[api] ') || str_starts_with($line, '[device] ')));
        self::assertCount(1, array_filter($output, static fn (string $line): bool => str_starts_with($line, '[sign_in] ')));
    }

    /**
     * A key too short is reported without the key.
     *
     * @return void
     */
    public function testNoSecretIsPrinted(): void
    {
        config()->set('authentication.jwt.keys', ['kid' => 'not-long-enough-secret']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertStringNotContainsString('not-long-enough-secret', implode("\n", $output));
    }

    /**
     * With `--guard`, only the named guards are checked; a named guard that is
     * not configured, or not a `jwt` guard, is a problem.
     *
     * @return void
     */
    public function testOnlyTheNamedGuardsAreChecked(): void
    {
        config()->set('auth.guards.admin.audience', ['methods' => []]);

        [$code, $output] = $this->check(['--guard' => ['api', 'web', 'missing', 'api']]);

        self::assertSame(1, $code);
        self::assertSame(['[device] OK', '[sign_in] OK', '[api] OK', '[web] Not a jwt guard.', '[missing] Not configured.'], $output);
    }

    /**
     * Without `jwt` guards there is nothing to check but the device model, and
     * the command says so and passes.
     *
     * @return void
     */
    public function testNoJwtGuardsIsSaidAndPasses(): void
    {
        config()->set('auth.guards', ['web' => ['driver' => 'session', 'provider' => 'users']]);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(['No jwt guards are configured.', '[device] OK', '[sign_in] OK'], $output);

        config()->set('auth.guards', null);

        self::assertSame([0, ['No jwt guards are configured.', '[device] OK', '[sign_in] OK']], $this->check());
    }

    /**
     * A guard whose name is all digits, which PHP keys as an integer, is
     * checked by its name.
     *
     * @return void
     */
    public function testAGuardNamedWithDigitsIsChecked(): void
    {
        config()->set('auth.guards', ['2024' => ['driver' => 'jwt', 'provider' => 'users']]);

        self::assertSame([0, ['[device] OK', '[sign_in] OK', '[2024] OK']], $this->check());
    }

    /**
     * An audience policy of the application's own reads its own settings, so
     * the package's audience settings are not checked for it.
     *
     * @return void
     */
    public function testTheAudienceSettingsOfAnApplicationPolicyAreNotChecked(): void
    {
        config()->set('auth.guards.api.audience', ['methods' => []]);

        $this->app?->instance(AudiencePolicy::class, \Mockery::mock(AudiencePolicy::class));

        self::assertSame(0, $this->check()[0]);
    }

    /**
     * A principal resolver override that resolves to a resolver passes.
     *
     * @return void
     */
    public function testAPrincipalResolverOverrideIsResolved(): void
    {
        config()->set('auth.guards.api.principal_resolver', StubReplacementPrincipalResolver::class);

        self::assertSame([0, ['[device] OK', '[sign_in] OK', '[api] OK', '[admin] OK']], $this->check());
    }

    /**
     * Register the package with a valid configuration: two `jwt` guards, a
     * session guard, and a database connection that cannot be opened.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class];
    }

    /**
     * Configure the guards, the keys and the device model, and a database
     * connection that fails if opened.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'unreachable');
        $config->set('database.connections.unreachable', ['driver' => 'sqlite', 'database' => '/nonexistent/directory/database.sqlite', 'prefix' => '']);
        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.jwt.keys', ['kid' => self::SECRET]);
        $config->set('authentication.jwt.active_kid', 'kid');
        $config->set('auth.providers.users', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'users']);
    }

    /**
     * Run the command and return its exit code and its output lines.
     *
     * @param  array<string, mixed>  $parameters
     * @return array{0: int, 1: list<string>}
     */
    private function check(array $parameters = []): array
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $code = $kernel->call('authentication:check', $parameters);

        return [$code, array_values(array_filter(array_map(trim(...), explode("\n", $kernel->output())), static fn (string $line): bool => $line !== ''))];
    }
}
