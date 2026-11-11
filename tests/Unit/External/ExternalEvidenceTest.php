<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;

/**
 * Unit tests for the evidence an external provider asserted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalEvidence::class)]
final class ExternalEvidenceTest extends TestCase
{
    /**
     * The evidence keeps what the provider asserted, its time cut to the second
     * and its bounds counted in characters.
     *
     * @return void
     */
    public function testTheEvidenceKeepsWhatTheProviderAsserted(): void
    {
        $evidence = new ExternalEvidence(['pwd', 'otp'], 'urn:mace:incommon:iap:silver', CarbonImmutable::parse('2026-04-06 11:58:00.7'));

        self::assertSame(['pwd', 'otp'], $evidence->methods);
        self::assertSame('urn:mace:incommon:iap:silver', $evidence->context);
        self::assertSame('2026-04-06 11:58:00.000000', $evidence->authenticatedAt->format('Y-m-d H:i:s.u'));

        $bare = new ExternalEvidence([], null, CarbonImmutable::parse('2026-04-06 11:58:00'));

        self::assertSame([[], null], [$bare->methods, $bare->context]);

        $widest = new ExternalEvidence(array_fill(0, 32, str_repeat('é', 255)), str_repeat('é', 1024), CarbonImmutable::parse('2026-04-06 11:58:00'));

        self::assertCount(ExternalEvidence::MAX_METHODS, $widest->methods);
        self::assertSame([32, 255, 1024], [ExternalEvidence::MAX_METHODS, ExternalEvidence::METHOD_MAX_LENGTH, ExternalEvidence::CONTEXT_MAX_LENGTH]);
    }

    /**
     * Rows of `[methods, context, message]` the evidence refuses.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: ?string, 2: string}>
     */
    public static function provideRefusedEvidence(): iterable
    {
        $methods = 'An external provider\'s method references must be a list of at most 32.';
        $method  = 'An external provider\'s method reference must be from 1 to 255 characters.';
        $context = 'An external provider\'s authentication context, when given, must be from 1 to 1024 characters.';

        yield from [
            'too many methods'          => [array_fill(0, 33, 'otp'), null, $methods],
            'methods that are keyed'    => [['first' => 'otp'], null, $methods],
            'methods out of order'      => [[1 => 'otp'], null, $methods],
            'an empty method'           => [['otp', ''], null, $method],
            'a long method'             => [[str_repeat('m', 256)], null, $method],
            'a method that is not text' => [[7], null, $method],
            'an empty context'          => [['otp'], '', $context],
            'a long context'            => [['otp'], str_repeat('c', 1025), $context],
        ];
    }

    /**
     * Method references that are not a short list of short strings, or a
     * context that is empty or too long, are refused.
     *
     * @param  array<array-key, mixed>  $methods
     * @param  ?string  $context
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedEvidence')]
    public function testTheEvidenceRefusesWhatDoesNotFit(array $methods, ?string $context, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new ExternalEvidence($methods, $context, CarbonImmutable::parse('2026-04-06 11:58:00')); // @phpstan-ignore argument.type
    }

    /**
     * Evidence whose stored JSON takes exactly the most bytes it may is kept,
     * and a byte more is refused.
     *
     * @return void
     */
    public function testTheEvidenceIsRefusedWhenItsStoredFormDoesNotFit(): void
    {
        $at      = CarbonImmutable::parse('2026-04-06 11:58:00');
        $methods = [...array_fill(0, 21, str_repeat("\u{1F600}", 255)), str_repeat("\u{1F600}", 80)];
        $room    = ExternalEvidence::STORED_MAX_BYTES - strlen((string) json_encode(['methods' => $methods, 'context' => '', 'authenticated_at' => $at->utc()->toIso8601String()]));
        $fits    = new ExternalEvidence($methods, str_repeat('c', $room), $at);

        self::assertSame(65535, ExternalEvidence::STORED_MAX_BYTES);
        self::assertSame(ExternalEvidence::STORED_MAX_BYTES, strlen((string) json_encode($fits->toArray())));

        foreach ([[$methods, str_repeat('c', $room + 1)], [["\xff"], null]] as [$refused, $context]) {
            try {
                new ExternalEvidence($refused, $context, $at);

                self::fail('The evidence should have been refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An external provider\'s evidence must be valid UTF-8 and at most 65535 bytes as stored.', $exception->getMessage());
            }
        }
    }

    /**
     * The stored form holds the time in UTC as ISO 8601 and reads back as the
     * same evidence.
     *
     * @return void
     */
    public function testTheStoredFormReadsBackAsTheSameEvidence(): void
    {
        $evidence = new ExternalEvidence(['hwk', 'pin'], 'phr', CarbonImmutable::parse('2026-04-06 13:58:00.4', 'Europe/Paris'));

        self::assertSame(['methods' => ['hwk', 'pin'], 'context' => 'phr', 'authenticated_at' => '2026-04-06T11:58:00+00:00'], $evidence->toArray());

        $read = ExternalEvidence::fromStored($evidence->toArray());

        self::assertNotNull($read);
        self::assertSame(['hwk', 'pin'], $read->methods);
        self::assertSame('phr', $read->context);
        self::assertSame($evidence->authenticatedAt->getTimestamp(), $read->authenticatedAt->getTimestamp());

        $bare = ExternalEvidence::fromStored((new ExternalEvidence([], null, CarbonImmutable::parse('2026-04-06 11:58:00')))->toArray());

        self::assertSame([[], null], [$bare?->methods, $bare?->context]);
    }

    /**
     * Rows of a stored value that holds no evidence.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedStoredValues(): iterable
    {
        $time = '2026-04-06T11:58:00+00:00';

        yield from [
            'nothing'                   => [null],
            'a string'                  => ['{"methods":[]}'],
            'no methods'                => [['context' => null, 'authenticated_at' => $time]],
            'methods that are text'     => [['methods' => 'otp', 'authenticated_at' => $time]],
            'methods out of bounds'     => [['methods' => [''], 'authenticated_at' => $time]],
            'methods that are keyed'    => [['methods' => ['a' => 'otp'], 'authenticated_at' => $time]],
            'no time'                   => [['methods' => ['otp']]],
            'a time that is a number'   => [['methods' => ['otp'], 'authenticated_at' => 1775476680]],
            'a time that is no time'    => [['methods' => ['otp'], 'authenticated_at' => 'yesterday-ish']],
            'a context that is no text' => [['methods' => ['otp'], 'context' => 7, 'authenticated_at' => $time]],
            'a context out of bounds'   => [['methods' => ['otp'], 'context' => '', 'authenticated_at' => $time]],
        ];
    }

    /**
     * A stored value that is not the stored form, or whose parts do not fit,
     * reads as no evidence rather than failing, so it never counts.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedStoredValues')]
    public function testAMalformedStoredValueIsNoEvidence(mixed $value): void
    {
        self::assertNull(ExternalEvidence::fromStored($value));
    }
}
