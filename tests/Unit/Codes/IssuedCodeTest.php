<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for a code just issued: it hands the code to the delivery job's
 * encrypted payload and to the sender, and shows it to no dump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuedCode::class)]
final class IssuedCodeTest extends TestCase
{
    /** @var string The code the tests issue. */
    private const string CODE = '8261937405';

    /**
     * The code is read in clear through `code()` and as a secret through
     * `secret()`, with the issuance and expiry beside it.
     *
     * @return void
     */
    public function testCarriesTheCodeTheIssuanceAndTheExpiry(): void
    {
        $expiresAt = CarbonImmutable::createStrict(2026, 4, 6, 12, 10, 0);
        $issued    = new IssuedCode(self::CODE, 'issue-1', $expiresAt);

        self::assertSame(self::CODE, $issued->code());
        self::assertInstanceOf(Secret::class, $issued->secret());
        self::assertSame(self::CODE, $issued->secret()->reveal());
        self::assertSame(['issue-1', $expiresAt], [$issued->issueId, $issued->expiresAt]);
    }

    /**
     * No dump shows the code (Laravel's VarDumper, `print_r`, `var_export`),
     * the debug information shows the placeholder beside the issuance, and the
     * constructor's parameter is sensitive.
     *
     * @return void
     */
    public function testTheCodeIsShownByNoDump(): void
    {
        $expiresAt = CarbonImmutable::createStrict(2026, 4, 6, 12, 10, 0);
        $issued    = new IssuedCode(self::CODE, 'issue-1', $expiresAt);

        $dumps = [
            (string) (new CliDumper)->dump((new VarCloner)->cloneVar($issued), true),
            print_r($issued, true),
            var_export($issued, true),
        ];

        foreach ($dumps as $dumped) {
            self::assertStringNotContainsString(self::CODE, $dumped);
            self::assertStringContainsString('issue-1', $dumped);
        }

        self::assertSame(['code' => Secret::REDACTED, 'issueId' => 'issue-1', 'expiresAt' => $expiresAt], $issued->__debugInfo());
        self::assertNotSame([], (new \ReflectionParameter([IssuedCode::class, '__construct'], 'code'))->getAttributes(\SensitiveParameter::class));
    }

    /**
     * Serialising, which only the encrypted delivery job's payload does, writes
     * the code in clear and reads it back whole: the job delivers the code it
     * was queued with.
     *
     * @return void
     */
    public function testTheJobPayloadRoundTripsTheCode(): void
    {
        $expiresAt = CarbonImmutable::createStrict(2026, 4, 6, 12, 10, 0);
        $issued    = new IssuedCode(self::CODE, 'issue-1', $expiresAt);

        self::assertSame(['code' => self::CODE, 'issue_id' => 'issue-1', 'expires_at' => $expiresAt], $issued->__serialize());

        $restored = unserialize(serialize($issued));

        self::assertInstanceOf(IssuedCode::class, $restored);
        self::assertSame(self::CODE, $restored->code());
        self::assertSame('issue-1', $restored->issueId);
        self::assertTrue($expiresAt->equalTo($restored->expiresAt));
        self::assertStringNotContainsString(self::CODE, print_r($restored, true));
    }
}
