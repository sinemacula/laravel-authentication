<?php

declare(strict_types = 1);

namespace Tests\Integration\Verification;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Concerns\RecordsEventSequences;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\TestCase;

/**
 * Proves each outcome of consuming a verification link is what it wrote and
 * reported, on whichever engine the suite runs against: the identifier recorded
 * verified only for `verified`, whose `IdentifierVerified` waits for the
 * commit, a failure reported for `invalid` and `expired` alone, and no sign-in
 * event, Laravel's or the package's, for any of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationLinks::class)]
final class VerificationLinkOutcomesTest extends TestCase
{
    use InteractsWithVerifiableIdentities, RecordsEventSequences;

    /** @var string Guard the links verify for. */
    private const string GUARD = 'api';

    /** @var string When the seeded identity's address was verified, where it starts verified. */
    private const string VERIFIED_BEFORE = '2027-01-01 00:00:00';

    /**
     * Freeze the clock, create the identities table and record the events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2027-03-01 08:30:00'));

        self::createVerifiableIdentitiesTable();

        $this->recordSequence();
    }

    /**
     * Drop the identities table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('verifiable_identities');
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Rows of `[whether the address starts verified, what happens before the
     * link is followed, outcome, address verified at, every authentication
     * event dispatched]`.
     *
     * @return iterable<string, array{0: bool, 1: string, 2: \SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome, 3: ?string, 4: list<string>}>
     */
    public static function provideOutcomes(): iterable
    {
        yield from [
            'verified'         => [false, 'nothing', VerificationLinkOutcome::VERIFIED, '2027-03-01 08:30:00', ['IdentifierVerified api i1/-/-']],
            'already verified' => [true, 'nothing', VerificationLinkOutcome::ALREADY_VERIFIED, self::VERIFIED_BEFORE, []],
            'mismatch'         => [false, 'race', VerificationLinkOutcome::MISMATCH, null, []],
            'invalid'          => [false, 'change', VerificationLinkOutcome::INVALID, null, ['AuthenticationFailed api identifier_verification:invalid_credentials i1/-/-']],
            'expired'          => [false, 'expire', VerificationLinkOutcome::EXPIRED, null, ['AuthenticationFailed api identifier_verification:link_expired -/-/-']],
        ];
    }

    /**
     * Each outcome leaves the identity's address and the events as it says.
     *
     * @param  bool  $verified
     * @param  string  $before
     * @param  \SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome  $outcome
     * @param  ?string  $verifiedAt
     * @param  list<string>  $events
     * @return void
     */
    #[DataProvider('provideOutcomes')]
    public function testEachOutcomeIsWhatTheLinkWroteAndReported(bool $verified, string $before, VerificationLinkOutcome $outcome, ?string $verifiedAt, array $events): void
    {
        $identity = self::seedVerifiableIdentity();

        $this->nameIdentities($identity);

        DB::table('verifiable_identities')->update(['email_verified_at' => $verified ? self::VERIFIED_BEFORE : null]);

        $link = $this->links()->create(self::GUARD, $identity, 'email', 'verify');

        $change = static fn (): int => DB::table('verifiable_identities')->update(['email' => 'eve@example.com']);

        match ($before) {
            'race'   => Event::listen('eloquent.retrieved: ' . VerifiableIdentity::class, $change),
            'change' => $change(),
            'expire' => Carbon::setTestNow(Carbon::now()->addHour()->addSecond()),
            default  => null,
        };

        self::assertSame($outcome, $this->links()->consume(Request::create($link)));
        self::assertSame($verifiedAt, self::verifiedAt());
        self::assertSame($events, $this->recordedSequence());
    }

    /**
     * Inside a transaction on the identity's connection, `IdentifierVerified`
     * waits for the commit, and a rolled-back verification is neither recorded
     * nor reported, so the link verifies once followed again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVerificationIsReportedOnlyOnceCommitted(): void
    {
        $identity = self::seedVerifiableIdentity();
        $link     = $this->links()->create(self::GUARD, $identity, 'email', 'verify');

        $this->nameIdentities($identity);

        DB::beginTransaction();

        self::assertSame(VerificationLinkOutcome::VERIFIED, $this->links()->consume(Request::create($link)));
        self::assertSame([], $this->recordedSequence());

        DB::rollBack();

        self::assertSame([], $this->recordedSequence());
        self::assertNull(self::verifiedAt());

        DB::transaction(function () use ($link): void {
            self::assertSame(VerificationLinkOutcome::VERIFIED, $this->links()->consume(Request::create($link)));
            self::assertSame([], $this->recordedSequence());
        });

        self::assertSame(['IdentifierVerified api i1/-/-'], $this->recordedSequence());
        self::assertSame('2027-03-01 08:30:00', self::verifiedAt());
    }

    /**
     * Configure the guard over the identities.
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

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'verifiable']);
        $config->set('auth.providers.verifiable', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
    }

    /**
     * Define the route verification links point at.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get('/verify', static fn (): string => 'ok')->name('verify');
    }

    /**
     * The links helper.
     *
     * @return \SineMacula\Laravel\Authentication\Verification\VerificationLinks
     */
    private function links(): VerificationLinks
    {
        return app(VerificationLinks::class);
    }

    /**
     * When the stored address was verified, as the engine holds it, or `null`.
     *
     * @return ?string
     */
    private static function verifiedAt(): ?string
    {
        $verifiedAt = DB::table('verifiable_identities')->value('email_verified_at');

        return is_string($verifiedAt) ? Carbon::parse($verifiedAt)->format('Y-m-d H:i:s') : null;
    }
}
