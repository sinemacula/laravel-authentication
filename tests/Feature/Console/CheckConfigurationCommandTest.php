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
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authentication\Console\PasswordChecks;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Passwords\NotifyingResetLinkSender;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubReplacementPrincipalResolver;

/**
 * Feature tests for `authentication:check`: it resolves each `jwt` and
 * `api_key` guard's settings and the device model as the package would, lists
 * every problem it finds as `[<guard>] <message>`, exits `1` when there is one
 * and `0` when there is none, and reads configuration only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
#[CoversClass(PasswordChecks::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    /** @var string A signing secret long enough for HS256. */
    private const string SECRET = 'a-signing-secret-of-at-least-32-bytes!!';

    /** @var list<string> What a run prints for the package-wide settings when none has a problem. */
    private const array PACKAGE_OK = ['[device] OK', '[sign_in] OK', '[passwords] OK', '[codes] OK', '[delivery] OK', '[passkeys] OK', '[api_keys] OK', '[identifier_changes] OK'];

    /** @var list<string> What a run prints when nothing the default setup configures has a problem. */
    private const array EVERY_SUBJECT_OK = [...self::PACKAGE_OK, '[api] OK', '[admin] OK', '[machine] OK'];

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
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
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
        yield 'a passkey options limit per identifier' => [
            ['auth.guards.api.rate_limits' => ['passkey_options' => ['per_identifier' => ['max' => 5, 'decay_seconds' => 60]]]],
            '[api] Rate limit `passkey_options.per_identifier` for guard [api] must be null: a request for passkey sign-in options',
        ];
        yield 'a malformed password identifier' => [
            ['auth.guards.api.sign_in' => ['password_identifier' => 'Email']],
            '[api] auth.guards.api.sign_in.password_identifier must name the identifier column',
        ];
        yield 'a malformed refresh token transport' => [
            ['auth.guards.api.refresh_token' => ['sources' => ['cookie']]],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.path` must be the path of the refresh route',
        ];
        yield 'a refresh cookie name PHP renames' => [
            ['authentication.refresh_token.cookie.name' => 'app.refresh'],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.name` must be a header or cookie name without `.`.',
        ];
        yield 'a refresh body field PHP renames' => [
            ['auth.guards.api.refresh_token' => ['body_field' => 'auth.refresh']],
            '[api] Refresh token transport for guard [api]: `refresh_token.body_field` must be a field name without `.`, spaces or brackets.',
        ];
        yield 'a refresh cookie path with a trailing newline' => [
            ['auth.guards.api.refresh_token' => ['sources' => ['cookie'], 'cookie' => ['path' => "/auth\n"]]],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.path` must be the path of the refresh route',
        ];
        yield 'a CSRF header a browser sends on its own' => [
            ['auth.guards.api.refresh_token' => ['cookie' => ['csrf_header' => 'content-type']]],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.csrf_header` must be a custom header, not one a browser sends on its own.',
        ];
        yield 'a CSRF header a browser sends on its own, spelled with an underscore' => [
            ['auth.guards.api.refresh_token' => ['cookie' => ['csrf_header' => 'Content_Type']]],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.csrf_header` must be a custom header, not one a browser sends on its own.',
        ];
        yield 'a Sec- CSRF header spelled with an underscore' => [
            ['auth.guards.api.refresh_token' => ['cookie' => ['csrf_header' => 'Sec_Fetch_Site']]],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.csrf_header` must be a custom header, not one a browser sends on its own.',
        ];
        yield 'a refresh cookie name with a trailing newline' => [
            ['authentication.refresh_token.cookie.name' => "refresh_token\n"],
            '[api] Refresh token transport for guard [api]: `refresh_token.cookie.name` must be a header or cookie name without `.`.',
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
        yield 'a password minimum below 8' => [
            ['authentication.passwords.min_length' => 7],
            '[passwords] authentication.passwords.min_length must be an integer from 8 to 128.',
        ];
        yield 'a password maximum below the minimum' => [
            ['authentication.passwords.min_length' => 20, 'authentication.passwords.max_length' => 19],
            '[passwords] authentication.passwords.max_length must be an integer from 20 to 4096.',
        ];
        yield 'a password composition rule that is not a boolean' => [
            ['authentication.passwords.symbols' => 'yes'],
            '[passwords] authentication.passwords.symbols must be true or false.',
        ];
        yield 'an unknown breached-check mode' => [
            ['authentication.passwords.breached.when_unavailable' => 'ignore'],
            '[passwords] authentication.passwords.breached.when_unavailable must be `reject` or `allow`.',
        ];
        yield 'a code length out of range' => [
            ['authentication.codes.length' => 4],
            '[codes] authentication.codes.length must be an integer from 6 to 10.',
        ];
        yield 'a resend cooldown longer than the code lifetime' => [
            ['authentication.codes.ttl_seconds' => 60, 'authentication.codes.resend_cooldown_seconds' => 61],
            '[codes] authentication.codes.resend_cooldown_seconds must be an integer from 0 to 60.',
        ];
        yield 'a codes key too short' => [
            ['authentication.codes.key' => 'too-short-for-a-key'],
            '[codes] authentication.codes.key must be a string of at least 32 bytes, or null to derive the key from `app.key`.',
        ];
        yield 'a code delivery connection not configured' => [
            ['authentication.delivery.queue.connection' => 'missing'],
            '[delivery] authentication.delivery.queue.connection must name a connection configured in `queue.connections`, or be null for `queue.default`.',
        ];
        yield 'a code method with no sender bound' => [
            ['auth.guards.api.audience' => ['methods' => ['password', 'phone_code']]],
            '[codes] Guards [api] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.',
        ];
        yield 'a passkey challenge lifetime out of range' => [
            ['authentication.passkeys.challenge_ttl_seconds' => 601],
            '[passkeys] authentication.passkeys.challenge_ttl_seconds must be an integer from 30 to 600 seconds.',
        ];
        yield 'a guard that allows passkeys without a relying party' => [
            ['auth.guards.api.audience' => ['methods' => ['password', 'passkey']]],
            '[api] Passkey relying party `id` for guard [api] must be a lower-case host name, not an IP address:',
        ];
        yield 'a guard that allows passkeys with an origin off its relying party' => [
            [
                'auth.guards.api.audience'                      => ['methods' => ['passkey']],
                'authentication.passkeys.relying_party.id'      => 'example.test',
                'authentication.passkeys.relying_party.origins' => ['https://example.org'],
            ],
            '[api] Passkey relying party `origins` for guard [api] must be a non-empty list of exact lower-case origins',
        ];
        yield 'a malformed passkeys block on a guard that does not allow passkeys' => [
            ['auth.guards.api.passkeys' => 'example.test'],
            '[api] Passkey configuration for guard [api]: the guard\'s `passkeys` overrides must be an array.',
        ];
        yield 'an API key prefix out of form' => [
            ['authentication.api_keys.prefix' => 'Acme'],
            '[api_keys] `authentication.api_keys.prefix` must be a lower-case letter',
        ];
        yield 'an API key rotation overlap beyond the maximum' => [
            ['authentication.api_keys.rotation_overlap_seconds' => 700000],
            '[api_keys] `authentication.api_keys.rotation_overlap_seconds` must be an integer from 0 to',
        ];
        yield 'an API key rotation overlap maximum out of range' => [
            ['authentication.api_keys.max_rotation_overlap_seconds' => 2592001],
            '[api_keys] `authentication.api_keys.max_rotation_overlap_seconds` must be an integer from 0 to 2592000 seconds.',
        ];
        yield 'an API key last-use throttle out of range' => [
            ['authentication.api_keys.last_used_throttle_seconds' => -1],
            '[api_keys] `authentication.api_keys.last_used_throttle_seconds` must be an integer from 0 to 86400 seconds.',
        ];
        yield 'an API key pruning retention out of range' => [
            ['authentication.api_keys.prune_after_days' => 'month'],
            '[api_keys] `authentication.api_keys.prune_after_days` must be an integer from 0 to 3650 days.',
        ];
        yield 'an api_key guard whose provider is not an identity provider' => [
            ['auth.guards.machine.provider' => 'missing'],
            '[machine] Auth guard [machine] provider must resolve to [SineMacula\Laravel\Authentication\Contracts\IdentityProvider]; got [null].',
        ];
        yield 'an api_key guard whose principal resolver is not one' => [
            ['auth.guards.machine.principal_resolver' => \stdClass::class],
            '[machine] Auth guard [machine] principal_resolver [stdClass] resolved to [stdClass]',
        ];
        yield 'an api_key guard whose audience is malformed' => [
            ['auth.guards.machine.audience' => ['methods' => 'api_key']],
            '[machine] Audience `methods` for guard [machine] must be a non-empty list',
        ];
        yield 'an api_key guard whose audience does not allow api keys' => [
            ['auth.guards.machine.audience' => ['methods' => ['password']]],
            '[machine] Audience `methods` of an api_key guard must list `api_key`, or every key it is presented is refused.',
        ];
        yield 'an api_key guard whose rate limits are malformed' => [
            ['auth.guards.machine.rate_limits' => ['api_key' => null]],
            '[machine] Rate limits for guard [machine]: the guard\'s `rate_limits` has an unknown key `api_key`.',
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
     * A sender bound for guards that allow a code sign-in method passes, and
     * delivery on a worker-backed connection raises no warning.
     *
     * @return void
     */
    public function testABoundSenderDeliversForTheCodeMethods(): void
    {
        config()->set([
            'auth.guards.api.audience'   => ['methods' => ['phone_code']],
            'auth.guards.admin.audience' => ['methods' => ['password', 'phone_code']],
            'queue.default'              => 'database',
            'queue.connections.database' => ['driver' => 'database'],
        ]);

        FakeOneTimeCodeSender::fake($this->app);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * Every `jwt` guard that allows a code method is named when no sender is
     * bound, a guard named with digits included; a guard of another driver is
     * not one, whatever its audience lists.
     *
     * @return void
     */
    public function testEveryGuardThatAllowsACodeMethodIsNamed(): void
    {
        config()->set([
            'auth.guards.api.audience'   => ['methods' => ['phone_code']],
            'auth.guards.2024'           => ['driver' => 'jwt', 'provider' => 'users', 'audience' => ['methods' => ['phone_code']]],
            'auth.guards.web.audience'   => ['methods' => ['phone_code']],
            'auth.guards.admin.audience' => ['methods' => ['password', 'email_code']],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[codes] Guards [api, admin, 2024] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.', $output);
    }

    /**
     * A code sign-in method the application registered for another identifier
     * type counts as a code method: a guard that allows only it is named when
     * no sender is bound, and warned about on a `sync` connection. A method of
     * another kind, or one that does not build as a sign-in method (whether the
     * manager refuses what its factory gives, or a typed factory throws a
     * `TypeError`), is not a code method, and no guard needs to list it.
     *
     * @return void
     */
    public function testAnApplicationsCodeMethodIsACodeMethod(): void
    {
        $manager = $this->app?->make(SignInMethodManager::class);

        assert($manager instanceof SignInMethodManager);

        $manager->extend('whatsapp_code', fn (Application $app): CodeSignIn => $app->make(CodeSignIn::class, ['type' => 'whatsapp']));
        $manager->extend('sso', fn (): SignInMethod => \Mockery::mock(SignInMethod::class));
        $manager->extend('broken', fn (): \stdClass => new \stdClass);
        $manager->extend('typed', fn (): SignInMethod => new \stdClass); // @phpstan-ignore return.type

        config()->set([
            'auth.guards.api.audience'   => ['methods' => ['whatsapp_code']],
            'auth.guards.admin.audience' => ['methods' => ['sso', 'broken']],
            'queue.connections.sync'     => ['driver' => 'sync'],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[codes] Guards [api] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.', $output);
        self::assertContains('[delivery] One-time codes are delivered on a `sync` queue connection, after each response in the web process; '
            . 'set `authentication.delivery.queue.connection` to a worker-backed connection in production.', $output);
    }

    /**
     * Delivering codes on a `sync` connection is a warning, not a problem, and
     * only when a guard allows a code sign-in method.
     *
     * @return void
     */
    public function testSynchronousCodeDeliveryIsAWarning(): void
    {
        config()->set([
            'queue.default'                            => 'database',
            'queue.connections.database'               => ['driver' => 'database'],
            'queue.connections.sync'                   => ['driver' => 'sync'],
            'authentication.delivery.queue.connection' => 'sync',
        ]);

        FakeOneTimeCodeSender::fake($this->app);

        $warning = '[delivery] One-time codes are delivered on a `sync` queue connection, after each response in the web process; '
            . 'set `authentication.delivery.queue.connection` to a worker-backed connection in production.';

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        config()->set('auth.guards.admin.audience', ['methods' => ['phone_code']]);

        self::assertSame([0, [...self::PACKAGE_OK, $warning, '[api] OK', '[admin] OK', '[machine] OK']], $this->check());
    }

    /**
     * Delivering codes on a `failover` connection that can fall back to `sync`
     * is a warning of its own, only when a guard allows a code sign-in method;
     * one whose connections are all worker-backed is not.
     *
     * @return void
     */
    public function testCodeDeliveryThatCanFallBackToSyncIsAWarning(): void
    {
        config()->set([
            'queue.default'                            => 'database',
            'queue.connections.database'               => ['driver' => 'database'],
            'queue.connections.sync'                   => ['driver' => 'sync'],
            'queue.connections.workers'                => ['driver' => 'failover', 'connections' => ['database']],
            'queue.connections.failover'               => ['driver' => 'failover', 'connections' => ['database', 'sync']],
            'authentication.delivery.queue.connection' => 'failover',
        ]);

        FakeOneTimeCodeSender::fake($this->app);

        $warning = '[delivery] One-time codes are delivered on a `failover` queue connection that can fall back to `sync`; each delivery is '
            . 'pushed after the response, and runs in the web process when it falls back. Set `authentication.delivery.queue.connection` '
            . 'to a worker-backed connection that cannot in production.';
        $checked = self::EVERY_SUBJECT_OK;

        self::assertSame([0, $checked], $this->check());

        config()->set('auth.guards.admin.audience', ['methods' => ['email_code']]);

        self::assertSame([0, [...self::PACKAGE_OK, $warning, ...array_slice($checked, count(self::PACKAGE_OK))]], $this->check());

        config()->set('authentication.delivery.queue.connection', 'workers');

        self::assertSame([0, $checked], $this->check());
    }

    /**
     * A delivery connection that is not configured is a problem and raises no
     * warning; a guard whose audience is malformed counts as allowing no code
     * method here, since its own checks report it.
     *
     * @return void
     */
    public function testMalformedSettingsAreReportedOnceWhereTheyBelong(): void
    {
        config()->set([
            'auth.guards.api.audience'                 => ['methods' => []],
            'auth.guards.admin.audience'               => ['methods' => ['phone_code']],
            'authentication.delivery.queue.connection' => 'missing',
            'authentication.identifier_changes'        => ['ttl_seconds' => 3600, 'recent_authentication_seconds' => '59'],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[device] OK',
            '[sign_in] OK',
            '[passwords] OK',
            '[passkeys] OK',
            '[api_keys] OK',
            '[admin] OK',
            '[machine] OK',
            '[codes] Guards [admin] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.',
            '[delivery] authentication.delivery.queue.connection must name a connection configured in `queue.connections`, or be null for `queue.default`.',
            '[identifier_changes] authentication.identifier_changes.recent_authentication_seconds must be an integer from 60 to 86400.',
            '[api] Audience `methods` for guard [api] must be a non-empty list of lower-case sign-in method names:'
                . ' set `authentication.audience.methods` or the guard\'s `audience.methods` override.',
        ], $output);
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
        self::assertSame([
            '[device] OK',
            '[sign_in] OK',
            '[passwords] OK',
            '[codes] OK',
            '[delivery] OK',
            '[passkeys] OK',
            '[api_keys] OK',
            '[identifier_changes] OK',
            '[api] OK',
            '[web] Not a jwt or api_key guard.',
            '[missing] Not configured.',
        ], $output);
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
        self::assertSame(['No jwt or api_key guards are configured.', ...self::PACKAGE_OK], $output);

        config()->set('auth.guards', null);

        self::assertSame([0, ['No jwt or api_key guards are configured.', ...self::PACKAGE_OK]], $this->check());
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

        self::assertSame([0, [...self::PACKAGE_OK, '[2024] OK']], $this->check());
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

        $policy = \Mockery::mock(AudiencePolicy::class);

        $policy->allows('allowsMethod')->andReturn(false);

        $this->app?->instance(AudiencePolicy::class, $policy);

        self::assertSame(0, $this->check()[0]);
    }

    /**
     * A package-wide `__Host-` cookie name, on the root path for the guard that
     * reads the cookie, passes for that guard and for the guards that read the
     * body or a header and never set the cookie.
     *
     * @return void
     */
    public function testAHostCookieNameBindsOnlyTheGuardThatReadsTheCookie(): void
    {
        config()->set([
            'authentication.refresh_token.cookie.name' => '__Host-refresh_token',
            'auth.guards.admin.refresh_token'          => ['sources' => ['cookie'], 'cookie' => ['path' => '/']],
        ]);

        $passing = $this->check();

        config()->set('auth.guards.admin.refresh_token.cookie.path', '/auth');

        $failing = $this->check();

        self::assertSame([0, self::EVERY_SUBJECT_OK], $passing);
        self::assertSame(1, $failing[0]);
    }

    /**
     * A principal resolver override that resolves to a resolver passes.
     *
     * @return void
     */
    public function testAPrincipalResolverOverrideIsResolved(): void
    {
        config()->set('auth.guards.api.principal_resolver', StubReplacementPrincipalResolver::class);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A guard that allows passkeys, or configures a relying party, passes with
     * a valid one; a guard that does neither needs none.
     *
     * @return void
     */
    public function testAGuardThatUsesPasskeysPassesWithAValidRelyingParty(): void
    {
        config()->set([
            'auth.guards.api.audience'                      => ['methods' => ['password', 'passkey']],
            'auth.guards.admin.passkeys'                    => ['id' => 'admin.example.test', 'origins' => ['https://admin.example.test']],
            'authentication.passkeys.relying_party.id'      => 'example.test',
            'authentication.passkeys.relying_party.origins' => ['https://example.test'],
        ]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * The audience of an api_key guard is not held to `api_key` under an
     * application's own policy, which reads its own settings.
     *
     * @return void
     */
    public function testAnApiKeyGuardsAudienceIsNotCheckedForAnApplicationPolicy(): void
    {
        config()->set('auth.guards.machine.audience', ['methods' => ['password']]);

        $policy = \Mockery::mock(AudiencePolicy::class);

        $policy->allows('allowsMethod')->andReturnFalse();

        $this->app?->instance(AudiencePolicy::class, $policy);

        self::assertSame(0, $this->check()[0]);
    }

    /**
     * A `jwt` guard whose identities live on another connection than the
     * devices cannot run a password reset or an identifier change's
     * confirmation: a warning for each such guard checked, naming both
     * connections, that leaves the exit code alone.
     *
     * @return void
     */
    public function testResetsAcrossConnectionsAreAWarning(): void
    {
        config()->set('database.connections.device_store', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('authentication.device.model', SeparateConnectionDevice::class);

        $warning = static fn (string $guard): string => "[{$guard}] Password resets and identifier changes spend their proof with their change to the identity "
            . 'in one transaction, so ' . IntegrationIdentity::class
            . ' must be on the device model\'s connection: the identity is on [unreachable], the devices on [device_store].';

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame([$warning('api'), $warning('admin')], array_values(array_filter($output, static fn (string $line): bool => str_contains($line, 'Password resets'))));

        [$code, $output] = $this->check(['--guard' => ['machine', 'api']]);

        self::assertSame(0, $code);
        self::assertSame([$warning('api')], array_values(array_filter($output, static fn (string $line): bool => str_contains($line, 'Password resets'))));
    }

    /**
     * While Laravel's notification is the reset link sender, a `jwt` guard
     * identifying passwords by anything but `email` is warned about; with a
     * sender of the application's own, or an `email` identifier, it is not.
     *
     * @return void
     */
    public function testTheDefaultSenderWithAnotherIdentifierIsAWarning(): void
    {
        config()->set('auth.guards.api.sign_in', ['password_identifier' => 'phone']);

        $warning = '[api] Password reset links are refused: the guard identifies passwords by [phone], and the bound '
            . NotifyingResetLinkSender::class . ', Laravel\'s notification, can only link an email address.';

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertContains($warning, $output);
        self::assertCount(1, array_filter($output, static fn (string $line): bool => str_contains($line, 'Password reset links')));

        FakePasswordResetLinkSender::fake($this->app);

        self::assertNotContains($warning, $this->check()[1]);
    }

    /**
     * Settings a guard's own checks report raise no reset warning: a malformed
     * password identifier, or a device model that is not one.
     *
     * @return void
     */
    public function testMalformedSettingsRaiseNoResetWarning(): void
    {
        config()->set('auth.guards.api.sign_in', ['password_identifier' => 'Not A Column']);

        self::assertSame([], array_values(array_filter($this->check()[1], static fn (string $line): bool => str_contains($line, 'Password reset'))));

        config()->set('authentication.device.model', \stdClass::class);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([], array_values(array_filter($output, static fn (string $line): bool => str_contains($line, 'Password reset'))));
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

        $config->set('app.key', 'base64:' . base64_encode('laravel-authentication test key!'));
        $config->set('database.default', 'unreachable');
        $config->set('database.connections.unreachable', ['driver' => 'sqlite', 'database' => '/nonexistent/directory/database.sqlite', 'prefix' => '']);
        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.jwt.keys', ['kid' => self::SECRET]);
        $config->set('authentication.jwt.active_kid', 'kid');
        $config->set('auth.providers.users', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'users']);
        $config->set('auth.providers.machines', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'machines', 'audience' => ['methods' => ['api_key']]]);
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
