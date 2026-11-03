<?php

declare(strict_types = 1);

namespace Tests\Unit\Freshness;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Freshness\FreshnessSettings;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * The operations the package names: each is an operation's name, and the
 * shipped configuration gives each a requirement. The class holds constants
 * only, so its constructor is private.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Operations::class)]
final class OperationsTest extends TestCase
{
    /**
     * Rows of `[operation]`: every name the class defines.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOperations(): iterable
    {
        yield from [
            'identifier change'       => [Operations::IDENTIFIER_CHANGE],
            'password establishment'  => [Operations::PASSWORD_ESTABLISHMENT],
            'factor change'           => [Operations::FACTOR_CHANGE],
            'first additional factor' => [Operations::FIRST_ADDITIONAL_FACTOR],
        ];
    }

    /**
     * The name is an operation's, and the shipped configuration requires a
     * freshness for it on a guard that sets none of its own.
     *
     * @param  string  $operation
     * @return void
     */
    #[DataProvider('provideOperations')]
    public function testTheShippedConfigurationRequiresFreshnessFor(string $operation): void
    {
        $settings = new FreshnessSettings(new Repository(['authentication' => require __DIR__ . '/../../../config/authentication.php']));

        self::assertTrue(FreshnessSettings::isOperation($operation));
        self::assertNotNull($settings->requirement('api', $operation));
    }

    /**
     * The shipped configuration takes only a fresh step-up for a factor change,
     * and only a fresh reauthentication, never the sign-in itself, for an
     * identity's first additional factor, each within 15 minutes.
     *
     * @return void
     */
    public function testTheShippedFactorOperationsTakeWhatTheyMust(): void
    {
        $settings = new FreshnessSettings(new Repository(['authentication' => require __DIR__ . '/../../../config/authentication.php']));

        $change = $settings->requirement('api', Operations::FACTOR_CHANGE);
        $first  = $settings->requirement('api', Operations::FIRST_ADDITIONAL_FACTOR);

        self::assertSame('first_additional_factor', Operations::FIRST_ADDITIONAL_FACTOR);
        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], $change?->proofs);
        self::assertSame([ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::EXTERNAL_REAUTHENTICATION], $first?->proofs);
        self::assertSame(900, $first->maxAgeSeconds);
        self::assertFalse($first->takes(ProofKind::FIRST_FACTOR));
    }

    /**
     * The constructor is private.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(Operations::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(Operations::class, $instance);
    }
}
