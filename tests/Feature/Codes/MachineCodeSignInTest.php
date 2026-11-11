<?php

declare(strict_types = 1);

namespace Tests\Feature\Codes;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\CodeMachineClient;
use Tests\TestCase;

/**
 * Feature tests holding the code sign-in methods to a machine having no
 * interactive sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSignIn::class)]
#[CoversClass(SignInAdmission::class)]
final class MachineCodeSignInTest extends TestCase
{
    use InteractsWithCodeIdentities;

    /** @var string The code the engine issues. */
    private const string CODE = '135790';

    /**
     * Create the table, issue a known code and record the failures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE]);

        $this->recordEvents([AuthenticationFailed::class]);
    }

    /**
     * Drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        parent::tearDown();
    }

    /**
     * Rows of `[method, identifier type, identifier]`: the package's code
     * sign-in methods and the machine's verified identifier each sends to.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideCodeMethods(): iterable
    {
        yield 'a code for its phone number' => [CodeSignIn::PHONE, 'phone', self::PHONE];
        yield 'a code for its email address' => [CodeSignIn::EMAIL, 'email', 'ada@example.test'];
    }

    /**
     * A machine holding the right code is refused at admission as
     * `machine_identity`.
     *
     * @param  string  $method
     * @param  string  $type
     * @param  string  $identifier
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCodeMethods')]
    public function testAMachineHoldingTheCodeIsRefused(string $method, string $type, string $identifier): void
    {
        self::seedCodeIdentity();

        $machine = CodeMachineClient::query()->sole();

        self::assertTrue($this->codeService('machines')->send($method, [$type => $identifier], self::requestClient())->isSent());

        $result = $this->sessions('machines')->signIn($method, [$type => $identifier, 'challenge' => self::challenge(), 'code' => self::CODE], self::requestContext());

        self::assertSame(FailureReason::MACHINE_IDENTITY, $result->reason);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FailureReason::MACHINE_IDENTITY, AuthenticationFlow::SIGN_IN, $method], [$failure->reason, $failure->flow, $failure->context->method]);
        EventContextAssertions::assertIdentity($machine, $failure->context);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(0, DB::table('authentication_sessions')->count());
    }

    /**
     * Configure the code guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }
}
