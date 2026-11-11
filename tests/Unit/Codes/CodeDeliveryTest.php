<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeDelivery;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;

/**
 * Unit tests for one delivery the engine is about to write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeDelivery::class)]
final class CodeDeliveryTest extends TestCase
{
    /** @var string The code delivered. */
    private const string CODE = '135790';

    /**
     * A delivery draws a new issuance and challenge id, both UUIDs, and stores
     * the code's keyed hash in that issuance under the key's digest.
     *
     * @return void
     */
    public function testDrawsAnIssuanceAndAChallenge(): void
    {
        [$keys, $binding, $now] = self::fixture();

        $delivery = CodeDelivery::for($keys, $binding, self::CODE, $now, 600);
        $other    = CodeDelivery::for($keys, $binding, self::CODE, $now, 600);

        self::assertSame($keys->binding($binding), $delivery->digest);
        self::assertNull($delivery->context);
        self::assertSame($keys->code($delivery->digest, $delivery->issueId, self::CODE), $delivery->hash);
        self::assertSame([$now, 600], [$delivery->now, $delivery->ttlSeconds]);
        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $delivery->challengeId);
        self::assertNotSame($delivery->issueId, $delivery->challengeId);
        self::assertNotSame([$delivery->issueId, $delivery->challengeId], [$other->issueId, $other->challengeId]);
    }

    /**
     * Each way of writing a delivery sets its own columns.
     *
     * @return void
     */
    public function testWritesTheColumnsOfEachWay(): void
    {
        [$keys, $binding, $now] = self::fixture();

        $delivery  = CodeDelivery::for($keys, $binding, self::CODE, $now, 600);
        $expiresAt = $now->addSeconds(300);
        $resend    = [
            'issue_id'   => $delivery->issueId,
            'code_hash'  => $delivery->hash,
            'deliveries' => 3,
            'issued_at'  => $now,
            'expires_at' => $expiresAt,
        ];

        self::assertSame($resend, $delivery->resend(2, $expiresAt));
        $challenge = ['challenge_id' => $delivery->challengeId, 'context' => null, 'attempts' => 0, 'consumed_at' => null];

        self::assertSame([...$challenge, ...$resend], $delivery->challenge(2, $expiresAt));
        self::assertEquals(
            [...$challenge, ...$resend, 'deliveries' => 1, 'expires_at' => $now->addSeconds(600), 'window_started_at' => $now],
            $delivery->window(),
        );
    }

    /**
     * The code issued carries the secret, the delivery's issuance, and the
     * challenge, expiry and resend time it was written for.
     *
     * @return void
     */
    public function testIssuesTheCodeForTheChallengeWritten(): void
    {
        [$keys, $binding, $now] = self::fixture();

        $delivery = CodeDelivery::for($keys, $binding, self::CODE, $now, 600);
        $issued   = $delivery->issued('challenge-1', $now->addSeconds(120), $now->addSeconds(60));

        self::assertSame([self::CODE, $delivery->issueId, 'challenge-1'], [$issued->code(), $issued->issueId, $issued->challengeId]);
        self::assertTrue($now->addSeconds(120)->equalTo($issued->expiresAt));
        self::assertTrue($now->addSeconds(60)->equalTo($issued->resendAvailableAt));
    }

    /**
     * The keys, a sign-in binding and a moment to deliver at.
     *
     * @return array{0: \SineMacula\Laravel\Authentication\Codes\CodeKeys, 1: \SineMacula\Laravel\Authentication\Codes\CodeBinding, 2: \Carbon\CarbonImmutable}
     */
    private static function fixture(): array
    {
        return [
            new CodeKeys(new Repository(['app' => ['key' => 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=']])),
            CodeBinding::signIn('mobile', 'phone', '+447700900123'),
            CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0),
        ];
    }
}
