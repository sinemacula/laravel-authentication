<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\RecordsSessionOrigin;
use Tests\Unit\Stubs\StubSession;

/**
 * Unit tests for the accessors behind what a session started with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(RecordsSessionOrigin::class)]
final class RecordsSessionOriginTest extends TestCase
{
    /**
     * The guard, the sign-in method and the type of identifier it used read the
     * recorded values as strings.
     *
     * @return void
     */
    public function testReadsTheRecordedGuardAndMethod(): void
    {
        $session = (new StubSession)->forceFill(['guard' => 'api', 'sign_in_method' => 'password', 'sign_in_identifier_type' => 'email']);

        self::assertSame('api', $session->getGuard());
        self::assertSame('password', $session->getSignInMethod());
        self::assertSame('email', $session->getSignInIdentifierType());
    }

    /**
     * Values that were never recorded read as `null`, and the guard and the
     * method read so when not loaded too, rather than failing.
     *
     * @return void
     */
    public function testValuesNotRecordedOrNotLoadedReadAsNull(): void
    {
        $recordedNull = (new StubSession)->forceFill(['guard' => null, 'sign_in_method' => null, 'sign_in_identifier_type' => null]);
        $notLoaded    = new StubSession;

        self::assertNull($recordedNull->getGuard());
        self::assertNull($recordedNull->getSignInMethod());
        self::assertNull($recordedNull->getSignInIdentifierType());
        self::assertNull($notLoaded->getGuard());
        self::assertNull($notLoaded->getSignInMethod());
    }

    /**
     * The identifier type a switch is held to is reported when it was not
     * loaded, rather than read as a sign-in that used no identifier.
     *
     * @return void
     */
    public function testAnIdentifierTypeNotLoadedIsReported(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Cannot read the session state of ' . StubSession::class . ': its `sign_in_identifier_type` attribute is not loaded.'
            . ' Select the column or override getSignInIdentifierType().',
        );

        (new StubSession)->forceFill(['guard' => 'api', 'sign_in_method' => 'password'])->getSignInIdentifierType();
    }

    /**
     * The column names are the shipped migration's.
     *
     * @return void
     */
    public function testNamesTheShippedColumns(): void
    {
        $session = new StubSession;

        self::assertSame('guard', $session->getGuardName());
        self::assertSame('sign_in_method', $session->getSignInMethodName());
        self::assertSame('sign_in_identifier_type', $session->getSignInIdentifierTypeName());
        self::assertSame('client_name', $session->getClientNameName());
        self::assertSame('platform', $session->getPlatformName());
        self::assertSame('created_ip', $session->getCreatedIpName());
        self::assertSame('created_user_agent', $session->getCreatedUserAgentName());
    }
}
