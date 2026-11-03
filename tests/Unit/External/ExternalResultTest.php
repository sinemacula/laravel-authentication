<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;

/**
 * Unit tests for a result an external identity provider verified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalResult::class)]
final class ExternalResultTest extends TestCase
{
    /**
     * A result keeps the connection, issuer and subject exactly as given, the
     * provider's times cut to the whole second, and the evidence as given;
     * nothing else is required.
     *
     * @return void
     */
    public function testKeepsWhatTheAdapterVerified(): void
    {
        $authenticated = CarbonImmutable::parse('2026-04-06 11:58:00.5');
        $deadline      = CarbonImmutable::parse('2026-04-06 20:00:00.9');
        $result        = new ExternalResult('Connection-7 ', 'https://idp.example.test/', 'Subject 1', 'tenant-3', $authenticated, $deadline, 'v12');

        self::assertSame(
            ['Connection-7 ', 'https://idp.example.test/', 'Subject 1', 'tenant-3', 'v12'],
            [$result->connectionId, $result->issuer, $result->subject, $result->tenantId, $result->policyVersion],
        );
        self::assertSame('2026-04-06 11:58:00.000000', $result->authenticatedAt?->format('Y-m-d H:i:s.u'));
        self::assertSame('2026-04-06 20:00:00.000000', $result->sessionNotAfter?->format('Y-m-d H:i:s.u'));

        $bare = new ExternalResult('c', 'i', 's');

        self::assertSame([null, null, null, null, null], [$bare->tenantId, $bare->authenticatedAt, $bare->sessionNotAfter, $bare->policyVersion, $bare->evidence]);

        $evidence = new ExternalEvidence(['otp'], 'urn:example:acr', $authenticated);

        self::assertSame($evidence, (new ExternalResult('c', 'i', 's', evidence: $evidence))->evidence);
    }

    /**
     * Evidence may be dated at the provider's time, before it, or with a result
     * that gives no time; evidence dated in a later second than the provider's
     * time is refused, while a later instant within the same second is the same
     * time once both are cut to the second.
     *
     * @return void
     */
    public function testRefusesEvidenceDatedAfterTheProvidersTime(): void
    {
        $at = CarbonImmutable::parse('2026-04-06 11:58:00.7');

        foreach ([$at->subSecond(), $at, $at->addMillisecond()] as $time) {
            $evidence = new ExternalEvidence(['mfa'], null, $time);

            self::assertSame($evidence, (new ExternalResult('c', 'i', 's', authenticatedAt: $at, evidence: $evidence))->evidence);
        }

        $later = new ExternalEvidence(['mfa'], null, $at->addSecond());

        self::assertSame($later, (new ExternalResult('c', 'i', 's', evidence: $later))->evidence);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An external result\'s evidence may not be dated after the provider authenticated the identity.');

        new ExternalResult('c', 'i', 's', authenticatedAt: $at, evidence: $later);
    }

    /**
     * Each value fits up to its length in characters, not bytes.
     *
     * @return void
     */
    public function testEachValueFitsUpToItsLengthInCharacters(): void
    {
        self::assertSame(
            [255, 2048, 1024, 64],
            [ExternalResult::ID_MAX_LENGTH, ExternalResult::ISSUER_MAX_LENGTH, ExternalResult::SUBJECT_MAX_LENGTH, ExternalResult::VERSION_MAX_LENGTH],
        );

        $wide = new ExternalResult(str_repeat('é', 255), str_repeat('é', 2048), str_repeat('é', 1024), str_repeat('é', 255), policyVersion: str_repeat('é', 64));

        self::assertSame(
            [str_repeat('é', 255), str_repeat('é', 2048), str_repeat('é', 1024), str_repeat('é', 255), str_repeat('é', 64)],
            [$wide->connectionId, $wide->issuer, $wide->subject, $wide->tenantId, $wide->policyVersion],
        );
    }

    /**
     * Rows of `[arguments, field, length]` a result refuses.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: int}>
     */
    public static function provideRefusedResults(): iterable
    {
        $valid = ['connectionId' => 'c', 'issuer' => 'i', 'subject' => 's'];

        yield from [
            'an empty connection' => [['connectionId' => ''] + $valid, 'connection id', 255],
            'a long connection'   => [['connectionId' => str_repeat('c', 256)] + $valid, 'connection id', 255],
            'an empty issuer'     => [['issuer' => ''] + $valid, 'issuer', 2048],
            'a long issuer'       => [['issuer' => str_repeat('i', 2049)] + $valid, 'issuer', 2048],
            'an empty subject'    => [['subject' => ''] + $valid, 'subject', 1024],
            'a long subject'      => [['subject' => str_repeat('s', 1025)] + $valid, 'subject', 1024],
            'an empty tenant'     => [['tenantId' => ''] + $valid, 'tenant id', 255],
            'a long tenant'       => [['tenantId' => str_repeat('t', 256)] + $valid, 'tenant id', 255],
            'an empty policy'     => [['policyVersion' => ''] + $valid, 'policy version', 64],
            'a long policy'       => [['policyVersion' => str_repeat('v', 65)] + $valid, 'policy version', 64],
        ];
    }

    /**
     * An empty value, or one longer than it may be, is refused, naming it.
     *
     * @param  array<string, mixed>  $arguments
     * @param  string  $field
     * @param  int  $length
     * @return void
     */
    #[DataProvider('provideRefusedResults')]
    public function testRefusesValuesThatDoNotFit(array $arguments, string $field, int $length): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('An external result\'s %s, when given, must be from 1 to %d characters.', $field, $length));

        new ExternalResult(...$arguments); // @phpstan-ignore argument.type
    }
}
