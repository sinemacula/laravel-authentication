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
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Console\ApplicationChecks;
use SineMacula\Laravel\Authentication\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authentication\Console\PasswordChecks;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Passwords\NotifyingResetLinkSender;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Fixtures\Sessions\RefusingApplicationPolicy;
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
#[CoversClass(ApplicationChecks::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    /** @var string A signing secret long enough for HS256. */
    private const string SECRET = 'a-signing-secret-of-at-least-32-bytes!!';

    /** @var list<string> What a run prints for the package-wide settings but the device model when none has a problem. */
    private const array DEVICELESS_OK = ['[storage] OK', ...self::SHARED_OK];

    /** @var list<string> What a run prints for the package-wide settings when none has a problem and a `jwt` guard is configured. */
    private const array PACKAGE_OK = ['[storage] OK', '[device] OK', ...self::SHARED_OK];

    /** @var list<string> What a run prints for the package-wide settings after the storage and device checks. */
    private const array SHARED_OK = ['[sign_in] OK', '[passwords] OK', '[codes] OK', '[delivery] OK', '[passkeys] OK', '[api_keys] OK', '[identifier_changes] OK'];

    /** @var string What a run prints for the `machine` guard when its application does not allow `api_key`. */
    private const string API_KEY_NOT_ALLOWED = '[machine] An api_key guard\'s application must allow `api_key`, or every key it is presented is refused: '
        . 'with the package\'s policy, list `api_key` in the guard\'s `application.methods`.';

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
        yield 'a malformed application' => [
            ['auth.guards.api.application' => ['methods' => null]],
            '[api] Application `methods` for guard [api] must be a list of lower-case sign-in method names',
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
        yield 'a storage connection that is not a name' => [
            ['authentication.storage.connection' => ['testing']],
            '[storage] `authentication.storage.connection` must be a connection name, or null or empty for the default connection.',
        ];
        yield 'a storage connection that is not configured' => [
            ['authentication.storage.connection' => 'missing'],
            '[storage] The connection [missing] the package\'s tables are to live on is not configured in `database.connections`.',
        ];
        yield 'a storage connection that is not configured beside counters of their own' => [
            ['authentication.storage.connection' => 'missing', 'authentication.rate_limits.connection' => 'unreachable'],
            '[storage] The connection [missing] the package\'s tables are to live on is not configured in `database.connections`.',
        ];
        yield 'a rate limits connection that is not a name' => [
            ['authentication.rate_limits.connection' => 1],
            '[storage] `authentication.rate_limits.connection` must be a connection name, or null or empty for the storage connection.',
        ];
        yield 'a rate limits connection that is not configured' => [
            ['authentication.rate_limits.connection' => 'counters'],
            '[storage] The connection [counters] the package\'s tables are to live on is not configured in `database.connections`.',
        ];
        yield 'a device model off the storage connection' => [
            ['authentication.device.model' => SeparateConnectionDevice::class],
            '[device] authentication.device.model [' . SeparateConnectionDevice::class . '] must live on the storage connection',
        ];
        yield 'a device model that is not one' => [
            ['authentication.device.model' => \stdClass::class],
            '[device] authentication.device.model must be a non-empty class-string of an Eloquent model',
        ];
        yield 'a pruning retention out of range' => [
            ['authentication.device.prune_after_days' => 3651],
            '[device] authentication.device.prune_after_days must be an integer from 0 to 3650.',
        ];
        yield 'a pending sign-in lifetime out of range' => [
            ['authentication.sign_in.pending_ttl_seconds' => 5],
            '[sign_in] authentication.sign_in.pending_ttl_seconds must be an integer from 30 to 3600.',
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
            ['auth.guards.api.application' => ['methods' => ['password', 'phone_code']]],
            '[codes] Guards [api] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.',
        ];
        yield 'a passkey challenge lifetime out of range' => [
            ['authentication.passkeys.challenge_ttl_seconds' => 601],
            '[passkeys] authentication.passkeys.challenge_ttl_seconds must be an integer from 30 to 600.',
        ];
        yield 'a guard that allows passkeys without a relying party' => [
            ['auth.guards.api.application' => ['methods' => ['password', 'passkey']]],
            '[api] Passkey relying party `id` for guard [api] must be a lower-case host name, not an IP address:',
        ];
        yield 'a guard that allows passkeys with an origin off its relying party' => [
            [
                'auth.guards.api.application'                   => ['methods' => ['passkey']],
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
            '[api_keys] authentication.api_keys.prefix must be a lower-case letter',
        ];
        yield 'an API key rotation overlap beyond the maximum' => [
            ['authentication.api_keys.rotation_overlap_seconds' => 700000],
            '[api_keys] authentication.api_keys.rotation_overlap_seconds must be an integer from 0 to',
        ];
        yield 'an API key rotation overlap maximum out of range' => [
            ['authentication.api_keys.max_rotation_overlap_seconds' => 2592001],
            '[api_keys] authentication.api_keys.max_rotation_overlap_seconds must be an integer from 0 to 2592000.',
        ];
        yield 'an API key last-use throttle out of range' => [
            ['authentication.api_keys.last_used_throttle_seconds' => -1],
            '[api_keys] authentication.api_keys.last_used_throttle_seconds must be an integer from 0 to 86400.',
        ];
        yield 'an API key pruning retention out of range' => [
            ['authentication.api_keys.prune_after_days' => 'month'],
            '[api_keys] authentication.api_keys.prune_after_days must be an integer from 0 to 3650.',
        ];
        yield 'an api_key guard whose provider is not an identity provider' => [
            ['auth.guards.machine.provider' => 'missing'],
            '[machine] Auth guard [machine] provider must resolve to [SineMacula\Laravel\Authentication\Contracts\IdentityProvider]; got [null].',
        ];
        yield 'an api_key guard whose principal resolver is not one' => [
            ['auth.guards.machine.principal_resolver' => \stdClass::class],
            '[machine] Auth guard [machine] principal_resolver [stdClass] resolved to [stdClass]',
        ];
        yield 'an api_key guard whose application is malformed' => [
            ['auth.guards.machine.application' => ['methods' => 'api_key']],
            '[machine] Application `methods` for guard [machine] must be a list of lower-case sign-in method names',
        ];
        yield 'an api_key guard whose application does not allow api keys' => [
            ['auth.guards.machine.application' => ['methods' => ['password']]],
            self::API_KEY_NOT_ALLOWED,
        ];
        yield 'an api_key guard whose application allows nothing' => [
            ['auth.guards.machine.application' => ['methods' => []]],
            self::API_KEY_NOT_ALLOWED,
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
            'auth.guards.api.application'                => ['methods' => null],
            'auth.guards.api.refresh_token'              => ['header' => ''],
            'authentication.device.model'                => '',
            'authentication.device.prune_after_days'     => -1,
            'authentication.sign_in.pending_ttl_seconds' => 'soon',
        ]);

        self::assertSame([1, [
            '[storage] OK',
            '[passwords] OK',
            '[codes] OK',
            '[delivery] OK',
            '[passkeys] OK',
            '[api_keys] OK',
            '[identifier_changes] OK',
            '[admin] OK',
            '[machine] OK',
            '[device] authentication.device.model must be a non-empty class-string of an Eloquent model implementing [' . EloquentDevice::class . ']; got [(empty string)].',
            '[device] authentication.device.prune_after_days must be an integer from 0 to 3650.',
            '[sign_in] authentication.sign_in.pending_ttl_seconds must be an integer from 30 to 3600.',
            '[api] Application `methods` for guard [api] must be a list of lower-case sign-in method names: set `authentication.application.methods` '
                . 'or the guard\'s `application.methods` override.',
            '[api] Refresh token transport for guard [api]: `refresh_token.header` must be a header or cookie name without `.`.',
        ]], $this->check());
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
            'auth.guards.api.application'   => ['methods' => ['phone_code']],
            'auth.guards.admin.application' => ['methods' => ['password', 'phone_code']],
            'queue.default'                 => 'database',
            'queue.connections.database'    => ['driver' => 'database'],
        ]);

        FakeOneTimeCodeSender::fake($this->app);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * Every `jwt` guard that allows a code method is named when no sender is
     * bound, a guard named with digits included; a guard of another driver is
     * not one, whatever its application lists.
     *
     * @return void
     */
    public function testEveryGuardThatAllowsACodeMethodIsNamed(): void
    {
        config()->set([
            'auth.guards.api.application'   => ['methods' => ['phone_code']],
            'auth.guards.2024'              => ['driver' => 'jwt', 'provider' => 'users', 'application' => ['methods' => ['phone_code']]],
            'auth.guards.web.application'   => ['methods' => ['phone_code']],
            'auth.guards.admin.application' => ['methods' => ['password', 'email_code']],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[codes] Guards [api, admin, 2024] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.', $output);
    }

    /**
     * A code sign-in method the application registered for another identifier
     * type counts as a code method: a guard that allows only it is named when
     * no sender is bound. A method of another kind, or one that does not build
     * as a sign-in method (whether the manager refuses what its factory gives,
     * or a typed factory throws a `TypeError`), is not a code method, and no
     * guard needs to list it.
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
            'auth.guards.api.application'   => ['methods' => ['whatsapp_code']],
            'auth.guards.admin.application' => ['methods' => ['sso', 'broken']],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertContains('[codes] Guards [api] allow a code sign-in method, but no ' . OneTimeCodeSender::class . ' is bound to deliver the codes.', $output);
    }

    /**
     * Delivering on a `sync` connection is a warning, not a problem, whenever a
     * `jwt` guard is configured, whatever its application allows: any of them
     * may send a password reset or an identifier change. With only `api_key`
     * guards, which deliver nothing, there is none.
     *
     * @return void
     */
    public function testSynchronousDeliveryIsAWarning(): void
    {
        config()->set([
            'queue.connections.sync'                   => ['driver' => 'sync'],
            'authentication.delivery.queue.connection' => 'sync',
        ]);

        $warning = '[delivery] One-time codes, password reset links and codes, and identifier change codes and notices are delivered on a `sync` '
            . 'queue connection, after each response in the web process; set `authentication.delivery.queue.connection` to a '
            . 'worker-backed connection in production.';

        self::assertSame([0, [...self::PACKAGE_OK, $warning, '[api] OK', '[admin] OK', '[machine] OK']], $this->check());

        config()->set('auth.guards', ['machine' => config('auth.guards.machine')]);

        self::assertSame([0, [...self::DEVICELESS_OK, '[machine] OK']], $this->check());
    }

    /**
     * Delivering on a `failover` connection that can fall back to `sync` is a
     * warning of its own, whenever a `jwt` guard is configured; one whose
     * connections are all worker-backed is not.
     *
     * @return void
     */
    public function testDeliveryThatCanFallBackToSyncIsAWarning(): void
    {
        config()->set([
            'queue.connections.sync'                   => ['driver' => 'sync'],
            'queue.connections.workers'                => ['driver' => 'failover', 'connections' => ['database']],
            'queue.connections.failover'               => ['driver' => 'failover', 'connections' => ['database', 'sync']],
            'authentication.delivery.queue.connection' => 'failover',
        ]);

        $warning = '[delivery] One-time codes, password reset links and codes, and identifier change codes and notices are delivered on a '
            . '`failover` queue connection that can fall back to `sync`; each delivery is pushed after the response, and runs in the '
            . 'web process when it falls back. Set `authentication.delivery.queue.connection` to a worker-backed connection that '
            . 'cannot in production.';
        $checked = self::EVERY_SUBJECT_OK;

        self::assertSame([0, [...self::PACKAGE_OK, $warning, ...array_slice($checked, count(self::PACKAGE_OK))]], $this->check());

        config()->set('authentication.delivery.queue.connection', 'workers');

        self::assertSame([0, $checked], $this->check());
    }

    /**
     * A delivery connection that is not configured is a problem and raises no
     * warning; a guard whose application is malformed counts as allowing no
     * code method here, since its own checks report it.
     *
     * @return void
     */
    public function testMalformedSettingsAreReportedOnceWhereTheyBelong(): void
    {
        config()->set([
            'auth.guards.api.application'              => ['methods' => ''],
            'auth.guards.admin.application'            => ['methods' => ['phone_code']],
            'authentication.delivery.queue.connection' => 'missing',
            'authentication.identifier_changes'        => ['ttl_seconds' => 3600, 'recent_authentication_seconds' => '59'],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[storage] OK',
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
            '[api] Application `methods` for guard [api] must be a list of lower-case sign-in method names:'
                . ' set `authentication.application.methods` or the guard\'s `application.methods` override.',
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
        config()->set('auth.guards.admin.application', ['methods' => []]);

        [$code, $output] = $this->check(['--guard' => ['api', 'web', 'missing', 'api']]);

        self::assertSame(1, $code);
        self::assertSame([
            '[storage] OK',
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
     * Without `jwt` guards there is nothing to check but the package-wide
     * settings, the device model's aside, and the command says so and passes.
     *
     * @return void
     */
    public function testNoJwtGuardsIsSaidAndPasses(): void
    {
        config()->set('auth.guards', ['web' => ['driver' => 'session', 'provider' => 'users']]);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(['No jwt or api_key guards are configured.', ...self::DEVICELESS_OK], $output);

        config()->set('auth.guards', null);

        self::assertSame([0, ['No jwt or api_key guards are configured.', ...self::DEVICELESS_OK]], $this->check());
    }

    /**
     * With only `api_key` guards, which keep no device sessions, the device
     * model is not checked: a configuration the `api_key` guard accepts, with
     * no device model at all, passes.
     *
     * @return void
     */
    public function testOnlyApiKeyGuardsLeaveTheDeviceModelUnchecked(): void
    {
        config()->set('auth.guards', ['machine' => config('auth.guards.machine')]);
        config()->set('authentication.device.model', '');

        self::assertSame([0, [...self::DEVICELESS_OK, '[machine] OK']], $this->check());

        config()->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users', 'application' => ['methods' => ['password']]]);

        [$code, $output] = $this->check(['--guard' => ['machine']]);

        self::assertSame(1, $code);
        self::assertContains('[machine] OK', $output);
        self::assertNotEmpty(array_filter($output, static fn (string $line): bool => str_starts_with($line, '[device] authentication.device.model must be')));
    }

    /**
     * A guard whose name is all digits, which PHP keys as an integer, is
     * checked by its name.
     *
     * @return void
     */
    public function testAGuardNamedWithDigitsIsChecked(): void
    {
        config()->set('auth.guards', ['2024' => ['driver' => 'jwt', 'provider' => 'users', 'application' => ['methods' => ['password']]]]);

        self::assertSame([0, [...self::PACKAGE_OK, '[2024] OK']], $this->check());
    }

    /**
     * An application policy of the application's own reads its own settings, so
     * the package's application settings are not checked for it: it is asked
     * instead, and a guard it allows nothing gets no warning, since the names
     * it allows are its own to know.
     *
     * @return void
     */
    public function testTheApplicationSettingsOfACustomPolicyAreNotChecked(): void
    {
        config()->set('auth.guards.api.application', ['methods' => null]);

        $allowed = ['api.password', 'machine.api_key'];
        $policy  = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andReturnUsing(static fn (string $guard, string $method): bool => in_array("{$guard}.{$method}", $allowed, true));

        $this->app?->instance(ApplicationPolicy::class, $policy);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A policy of the application's own that throws when it is asked is a
     * problem for each guard it was asked about, and gives no warning.
     *
     * @return void
     */
    public function testACustomPolicyThatThrowsIsAProblemForEachGuard(): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andThrow(new \InvalidArgumentException('Unreadable policy settings.'));

        $this->app?->instance(ApplicationPolicy::class, $policy);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([...self::PACKAGE_OK, '[api] Unreadable policy settings.', '[admin] Unreadable policy settings.', '[machine] Unreadable policy settings.'], $output);
    }

    /**
     * Rows of `[a name, what a policy of the application's own throws when
     * asked it]`, for every name it is asked for a `jwt` guard: every
     * registered sign-in method and `client_credentials`, each with an argument
     * exception and with an exception of another kind.
     *
     * @return iterable<string, array{0: string, 1: \Exception}>
     */
    public static function provideAskedNames(): iterable
    {
        foreach (['password', 'phone_code', 'email_code', 'passkey', 'client_credentials'] as $name) {
            yield "{$name}, an argument exception" => [$name, new \InvalidArgumentException("Unreadable `{$name}` setting.")];
            yield "{$name}, an exception of another kind" => [$name, new \RuntimeException("Policy store down for `{$name}`.")];
        }
    }

    /**
     * A policy of the application's own that throws only when asked the name is
     * a problem for each `jwt` guard, reported once, so every name is asked of
     * it, the code methods the code check asks about included, and nothing it
     * throws stops the run; the `api_key` guard, asked only `api_key`, passes.
     *
     * @param  string  $name
     * @param  \Exception  $exception
     * @return void
     */
    #[DataProvider('provideAskedNames')]
    public function testACustomPolicyIsAskedEveryNameAJwtGuardCouldUse(string $name, \Exception $exception): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andReturnUsing(static function (string $guard, string $method) use ($name, $exception): bool {
            if ($method === $name) {
                throw $exception;
            }

            return true;
        });

        $this->app?->instance(ApplicationPolicy::class, $policy);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        $message = $exception->getMessage();

        self::assertSame(["[api] {$message}", "[admin] {$message}"], array_values(array_filter($output, static fn (string $line): bool => str_ends_with($line, $message))));
        self::assertContains('[machine] OK', $output);
    }

    /**
     * Rows of `[the guards named with `--guard`, what a policy of the
     * application's own throws when asked `phone_code`, what the run prints]`.
     *
     * @return iterable<string, array{0: list<string>, 1: \Exception, 2: list<string>}>
     */
    public static function provideGuardsLeftOut(): iterable
    {
        $problem = static fn (string $guard, string $message): string => "[codes] Guard [{$guard}]'s application policy could not say"
            . " whether it allows a code sign-in method: {$message}";
        $before = ['[storage] OK', '[device] OK', '[sign_in] OK', '[passwords] OK', '[delivery] OK', '[passkeys] OK', '[api_keys] OK', '[identifier_changes] OK'];

        foreach ([new \InvalidArgumentException('Unreadable `phone_code` setting.'), new \RuntimeException('Policy store down.')] as $exception) {

            $message = $exception->getMessage();
            $kind    = $exception::class;

            yield "only the api_key guard, {$kind}" => [['machine'], $exception, [...$before, '[machine] OK', $problem('api', $message), $problem('admin', $message)]];
            yield "one jwt guard, {$kind}" => [['api'], $exception, [...$before, $problem('admin', $message), "[api] {$message}"]];
        }
    }

    /**
     * A policy of the application's own that throws when asked whether a `jwt`
     * guard left out of the run with `--guard` allows a code sign-in method is
     * a `[codes]` problem for that guard, reported once, since no check of the
     * guard's own asks again; a named guard reports it as its own problem.
     *
     * @param  list<string>  $guards
     * @param  \Exception  $exception
     * @param  list<string>  $output
     * @return void
     */
    #[DataProvider('provideGuardsLeftOut')]
    public function testAPolicyThatThrowsForAGuardLeftOutIsACodesProblem(array $guards, \Exception $exception, array $output): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andReturnUsing(static function (string $guard, string $method) use ($exception): bool {
            if ($method === 'phone_code') {
                throw $exception;
            }

            return $method !== 'passkey';
        });

        $this->app?->instance(ApplicationPolicy::class, $policy);

        self::assertSame([1, $output], $this->check(['--guard' => $guards]));
    }

    /**
     * The package's policy throws over settings it cannot read, so a `jwt`
     * guard left out of the run with `--guard` whose `methods` names a method
     * no sign-in method can have is a `[codes]` problem for that guard, and the
     * run fails, though no check of the guard's own runs.
     *
     * @return void
     */
    public function testThePackagePolicyOverUnreadableSettingsOfAGuardLeftOutIsACodesProblem(): void
    {
        config()->set('auth.guards.admin.application.methods', ['Password']);

        $problem = '[codes] Guard [admin]\'s application policy could not say whether it allows a code sign-in method: Application `methods` for'
            . ' guard [admin] must be a list of lower-case sign-in method names: set `authentication.application.methods` or the guard\'s'
            . ' `application.methods` override.';

        $before = ['[storage] OK', '[device] OK', '[sign_in] OK', '[passwords] OK', '[delivery] OK', '[passkeys] OK', '[api_keys] OK', '[identifier_changes] OK'];

        self::assertSame([1, [...$before, '[machine] OK', $problem]], $this->check(['--guard' => ['machine']]));
    }

    /**
     * Rows of `[whether a policy of the application's own allows the api_key
     * guard `api_key`, the exit code, what the run prints]`.
     *
     * @return iterable<string, array{0: bool, 1: int, 2: list<string>}>
     */
    public static function provideApiKeyAnswers(): iterable
    {
        yield 'allowed' => [true, 0, self::EVERY_SUBJECT_OK];
        yield 'not allowed' => [false, 1, [...self::PACKAGE_OK, '[api] OK', '[admin] OK', self::API_KEY_NOT_ALLOWED]];
    }

    /**
     * An `api_key` guard has no other use, so its application must allow
     * `api_key` under a policy of the application's own too: one that does
     * passes, and one that does not is a problem for the guard.
     *
     * @param  bool  $allowsKeys
     * @param  int  $code
     * @param  list<string>  $output
     * @return void
     */
    #[DataProvider('provideApiKeyAnswers')]
    public function testAnApiKeyGuardMustAllowApiKeysUnderACustomPolicy(bool $allowsKeys, int $code, array $output): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andReturnUsing(static fn (string $guard, string $method): bool => $method === 'password' || ($method === 'api_key' && $allowsKeys));

        $this->app?->instance(ApplicationPolicy::class, $policy);

        self::assertSame([$code, $output], $this->check());
    }

    /**
     * A policy of the application's own that wraps the package's, as one that
     * decides which principals may use an application does, keeps every check
     * that asks the policy: an `api_key` guard must allow `api_key`, and a
     * guard it allows `passkey` needs a relying party. Only the warning about
     * an application that allows nothing, which reads the package's settings,
     * is given for the package's policy alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPolicyWrappingThePackagesKeepsTheChecksThatAskIt(): void
    {
        config()->set([
            'auth.guards.api.application'     => ['methods' => []],
            'auth.guards.admin.application'   => ['methods' => ['password', 'passkey']],
            'auth.guards.machine.application' => ['methods' => []],
        ]);

        $relyingParty = '[admin] Passkey relying party `id` for guard [admin] must be a lower-case host name, not an IP address: set '
            . '`authentication.passkeys.relying_party.id` or the guard\'s `passkeys.id` override.';

        $package = $this->check();

        $this->app?->instance(ApplicationPolicy::class, new RefusingApplicationPolicy($this->app->make(GuardApplicationPolicy::class), static fn (): bool => false));

        self::assertSame([1, [...self::PACKAGE_OK, self::nothingAllowed('api'), '[api] OK', $relyingParty, self::API_KEY_NOT_ALLOWED]], $package);
        self::assertSame([1, [...self::PACKAGE_OK, '[api] OK', $relyingParty, self::API_KEY_NOT_ALLOWED]], $this->check());
    }

    /**
     * Only the `jwt` guards that allow nothing are warned about, wherever they
     * come among the guards checked.
     *
     * @return void
     */
    public function testOnlyTheGuardsThatAllowNothingAreWarned(): void
    {
        config()->set('auth.guards.admin.application', ['methods' => []]);

        self::assertSame([0, [...self::PACKAGE_OK, self::nothingAllowed('admin'), '[api] OK', '[admin] OK', '[machine] OK']], $this->check());
    }

    /**
     * A `jwt` guard that allows nothing, by its own empty list or the package
     * default, is a warning naming the guard, not a problem: the exit code is
     * `0` and the guard is still reported as checked.
     *
     * @return void
     */
    public function testAJwtGuardThatAllowsNothingIsAWarning(): void
    {
        config()->set([
            'auth.guards.api.application' => ['methods' => []],
            'auth.guards.admin'           => ['driver' => 'jwt', 'provider' => 'users'],
        ]);

        self::assertSame([0, [...self::PACKAGE_OK, self::nothingAllowed('api'), self::nothingAllowed('admin'), '[api] OK', '[admin] OK', '[machine] OK']], $this->check());
    }

    /**
     * Rows of `[what a jwt guard lists, whether it is warned about]`: it is
     * warned about only when it lists nothing but `api_key`, which allows
     * nothing on a `jwt` guard; any other name counts, registered or not, since
     * the application may start sessions under it itself.
     *
     * @return iterable<string, array{0: list<string>, 1: bool}>
     */
    public static function provideAllowedNames(): iterable
    {
        yield 'only api_key' => [['api_key'], true];
        yield 'client_credentials' => [['client_credentials'], false];
        yield 'a package method' => [['passkey'], false];
        yield 'a method the application registered' => [['sso'], false];
        yield 'a name nothing is registered under' => [['unregistered'], false];
        yield 'api_key and a name nothing is registered under' => [['api_key', 'unregistered'], false];
    }

    /**
     * Whether a `jwt` guard that lists only the names is warned about.
     *
     * @param  list<string>  $methods
     * @param  bool  $warned
     * @return void
     */
    #[DataProvider('provideAllowedNames')]
    public function testOnlyAGuardThatAllowsNoUsableNameIsWarned(array $methods, bool $warned): void
    {
        $manager = $this->app?->make(SignInMethodManager::class);

        assert($manager instanceof SignInMethodManager);

        $manager->extend('sso', fn (): SignInMethod => \Mockery::mock(SignInMethod::class));

        config()->set([
            'auth.guards.api.application'                   => ['methods' => $methods],
            'authentication.passkeys.relying_party.id'      => 'example.test',
            'authentication.passkeys.relying_party.origins' => ['https://example.test'],
        ]);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame($warned, in_array(self::nothingAllowed('api'), $output, true));
        self::assertContains('[api] OK', $output);
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
            'auth.guards.api.application'                   => ['methods' => ['password', 'passkey']],
            'auth.guards.admin.passkeys'                    => ['id' => 'admin.example.test', 'origins' => ['https://admin.example.test']],
            'authentication.passkeys.relying_party.id'      => 'example.test',
            'authentication.passkeys.relying_party.origins' => ['https://example.test'],
        ]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * A `jwt` guard whose identities live on another connection than the
     * storage connection cannot run a password reset or an identifier change's
     * confirmation: a warning for each such guard checked, naming both
     * connections, that leaves the exit code alone.
     *
     * @return void
     */
    public function testResetsAcrossConnectionsAreAWarning(): void
    {
        config()->set('database.connections.device_store', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('authentication.storage.connection', SeparateConnectionDevice::CONNECTION);

        $warning = static fn (string $guard): string => "[{$guard}] Password resets and identifier changes spend their proof with their change to the identity "
            . 'in one transaction, so ' . IntegrationIdentity::class
            . ' must be on the storage connection (`authentication.storage.connection`): the identity is on [unreachable], the package\'s tables on [device_store].';

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
     * Settings other checks report raise no reset warning: a malformed password
     * identifier, or a storage connection that is not a name.
     *
     * @return void
     */
    public function testMalformedSettingsRaiseNoResetWarning(): void
    {
        config()->set('auth.guards.api.sign_in', ['password_identifier' => 'Not A Column']);

        self::assertSame([], array_values(array_filter($this->check()[1], static fn (string $line): bool => str_contains($line, 'Password reset'))));

        config()->set('auth.guards.api.sign_in', []);
        config()->set('authentication.storage.connection', ['testing']);

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
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users', 'application' => ['methods' => ['password']]]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'users', 'application' => ['methods' => ['password']]]);
        $config->set('auth.providers.machines', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'machines', 'application' => ['methods' => ['api_key']]]);
        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database']);
    }

    /**
     * The warning about a `jwt` guard that allows nothing.
     *
     * @param  string  $guard
     * @return string
     */
    private static function nothingAllowed(string $guard): string
    {
        return "[{$guard}] Allows no sign-in method or machine credential: every sign-in, refresh, code and password reset request is refused as "
            . '`method_not_allowed` and every client credentials exchange as `unauthorized_client`. List the methods the application uses in '
            . 'the guard\'s `application.methods` (or `authentication.application.methods`).';
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
