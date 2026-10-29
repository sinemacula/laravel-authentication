<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks;
use SineMacula\Laravel\Authentication\IdentifierChanges\PresentedChangeLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\RequestedChange;
use Tests\TestCase;

/**
 * Feature tests for the signed links that confirm identifier changes, through
 * Laravel's URL generator: which routes and parameters can carry one, what a
 * link carries, and how a request to one is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChangeLinks::class)]
#[CoversClass(PresentedChangeLink::class)]
final class ChangeLinksTest extends TestCase
{
    /**
     * Freeze the clock and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-04-06 12:00:00'));

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A reserved name is refused as a parameter's name, never as its value.
     *
     * @return void
     */
    public function testOnlyReservedNamesAreRefused(): void
    {
        $links = self::links();

        $links->assertRoute('email.confirm', ['tab' => 'request', 'section' => 'hash']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier change link parameters may not use the reserved names: guard.');

        $links->assertRoute('email.confirm', ['guard' => 'admin']);
    }

    /**
     * A signed link carries the change's fields and its digest, and reads back
     * as the change it names; one whose signature has passed its time reads as
     * expired.
     *
     * @return void
     */
    public function testALinkReadsBackAsTheChangeItNames(): void
    {
        $change = new RequestedChange('email', 'ada@example.test', true, 'ada@new.example.test', 'request-1', CarbonImmutable::now(), CarbonImmutable::now()->addHour());
        $link   = self::links()->sign('email.confirm', ['tab' => 'profile'], 'web', '7', $change);
        $read   = self::links()->read(Request::create($link));

        self::assertInstanceOf(PresentedChangeLink::class, $read);
        self::assertSame(['web', '7', 'email', 'request-1', hash('sha256', 'ada@new.example.test')], [$read->guard, $read->identity, $read->type, $read->requestId, $read->hash]);
        self::assertSame(hash('sha256', 'ada@new.example.test'), ChangeLinks::digest('ada@new.example.test'));

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addHour()->addSecond());

        self::assertSame(FailureReason::LINK_EXPIRED, self::links()->read(Request::create($link)));
    }

    /**
     * A link with the right signature but another purpose, or missing a field,
     * is invalid.
     *
     * @return void
     */
    public function testALinkOfAnotherPurposeOrMissingAFieldIsInvalid(): void
    {
        $fields = ['guard' => 'web', 'identity' => '7', 'type' => 'email', 'request' => 'request-1', 'hash' => 'digest'];

        foreach ([[...$fields, 'purpose' => 'verify_identifier'], $fields] as $query) {
            $link = URL::temporarySignedRoute('email.confirm', CarbonImmutable::now()->addHour(), $query);

            self::assertSame(FailureReason::INVALID_CREDENTIALS, self::links()->read(Request::create($link)));
        }
    }

    /**
     * The links, signed by the application's URL generator.
     *
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks
     */
    private static function links(): ChangeLinks
    {
        return new ChangeLinks(app(UrlGenerator::class));
    }
}
