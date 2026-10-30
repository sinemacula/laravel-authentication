<?php

declare(strict_types = 1);

namespace Tests\Integration\IdentifierChanges;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Integration tests for how pending identifier changes are keyed, expire and
 * bind their code, which read no row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingChanges::class)]
final class PendingChangesTest extends TestCase
{
    /**
     * A pending change is keyed by the SHA-256 digest of the identity's account
     * and the type, joined by a NUL byte: one per identity and type, the same
     * through every guard.
     *
     * @return void
     */
    public function testAChangeIsKeyedByTheIdentitysAccountAndTheType(): void
    {
        $identity = new PlainIdentityFixture(7);

        self::assertSame(hash('sha256', AccountAttempts::account($identity) . "\0email"), PendingChanges::key($identity, 'email'));
        self::assertNotSame(PendingChanges::key($identity, 'email'), PendingChanges::key($identity, 'phone'));
        self::assertNotSame(PendingChanges::key($identity, 'email'), PendingChanges::key(new PlainIdentityFixture(8), 'email'));
    }

    /**
     * A change has expired from the second its expiry names.
     *
     * @return void
     */
    public function testAChangeExpiresFromTheSecondItNames(): void
    {
        $change = (new IdentifierChange)->forceFill(['expires_at' => '2026-04-06 13:00:00']);

        self::assertFalse(PendingChanges::hasExpired($change, CarbonImmutable::parse('2026-04-06 12:59:59')));
        self::assertTrue(PendingChanges::hasExpired($change, CarbonImmutable::parse('2026-04-06 13:00:00')));
    }

    /**
     * The code of a change is bound to its guard, type, new identifier, the
     * identity and its request.
     *
     * @return void
     */
    public function testTheCodeIsBoundToTheRequest(): void
    {
        $identity = new PlainIdentityFixture(7);
        $change   = (new IdentifierChange)->forceFill(['guard' => 'web', 'type' => 'email', 'identifier' => 'ada@new.example.test', 'request_id' => 'request-1']);
        $binding  = PendingChanges::binding($change, $identity);

        self::assertSame(
            [CodePurpose::CHANGE_IDENTIFIER, 'web', 'email', 'ada@new.example.test', AccountAttempts::account($identity) . "\0request-1"],
            [$binding->purpose, $binding->guard, $binding->type, $binding->identifier, $binding->identity],
        );
    }

    /**
     * The class holds no state and cannot be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PendingChanges::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PendingChanges::class, $instance);
    }
}
