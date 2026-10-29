<?php

declare(strict_types = 1);

namespace Tests\Unit\IdentifierChanges;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest;

/**
 * Unit tests for the answer to a request to change an identifier: each status
 * carries only what it says, and a link is never exposed by a dump or
 * serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeRequest::class)]
final class IdentifierChangeRequestTest extends TestCase
{
    /** @var string A signed link, as the URL generator returns one. */
    private const string LINK = 'https://app.example.test/email/confirm?request=r&signature=secret-signature';

    /**
     * A sent change carries when it expires and, for a link, the link; nothing
     * else.
     *
     * @return void
     */
    public function testASentChangeCarriesItsExpiryAndLink(): void
    {
        $expiresAt = CarbonImmutable::parse('2027-03-01 09:30:00');
        $byCode    = IdentifierChangeRequest::sent($expiresAt);
        $byLink    = IdentifierChangeRequest::sent($expiresAt, self::LINK);

        foreach ([[$byCode, null], [$byLink, self::LINK]] as [$request, $link]) {
            self::assertSame([IdentifierChangeRequestStatus::SENT, true], [$request->status, $request->isSent()]);
            self::assertSame([$expiresAt, null, $link], [$request->expiresAt, $request->retryAfter, $request->link()]);
        }
    }

    /**
     * Each refusal carries its status, and only a rate limit its wait.
     *
     * @return void
     */
    public function testRefusalsCarryTheirStatus(): void
    {
        $refusals = [
            [IdentifierChangeRequest::rateLimited(42), IdentifierChangeRequestStatus::RATE_LIMITED, 42],
            [IdentifierChangeRequest::reauthenticationRequired(), IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, null],
            [IdentifierChangeRequest::identifierInvalid(), IdentifierChangeRequestStatus::IDENTIFIER_INVALID, null],
            [IdentifierChangeRequest::identifierUnchanged(), IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED, null],
        ];

        foreach ($refusals as [$request, $status, $retryAfter]) {
            self::assertSame([$status, null, $retryAfter, null, false], [$request->status, $request->expiresAt, $request->retryAfter, $request->link(), $request->isSent()]);
        }
    }

    /**
     * No dump of a request shows its link, nor does JSON, and it cannot be
     * serialised.
     *
     * @return void
     */
    public function testTheLinkIsNeverExposed(): void
    {
        $request = IdentifierChangeRequest::sent(CarbonImmutable::parse('2027-03-01 09:30:00'), self::LINK);

        self::assertStringNotContainsString('secret-signature', print_r($request, true));
        self::assertStringNotContainsString('secret-signature', var_export($request, true));
        self::assertStringNotContainsString('secret-signature', (string) json_encode($request));

        $this->expectException(\Exception::class);

        serialize($request);
    }
}
