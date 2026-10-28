<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\DeferredCounterCheck;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Unit tests for the counter check handed to the WebAuthn library: it never
 * refuses, since the package applies its own rule atomically afterwards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeferredCounterCheck::class)]
final class DeferredCounterCheckTest extends TestCase
{
    /**
     * A count below, equal to or above the stored one passes the library's
     * check without an exception.
     *
     * @return void
     */
    #[DoesNotPerformAssertions]
    public function testEveryCountPassesTheLibrarysCheck(): void
    {
        $record = CredentialRecord::create('id', 'public-key', [], 'none', EmptyTrustPath::create(), Uuid::v4(), 'key', 'handle', 10);
        $check  = new DeferredCounterCheck;

        foreach ([0, 9, 10, 11] as $count) {
            $check->check($record, $count);
        }
    }
}
