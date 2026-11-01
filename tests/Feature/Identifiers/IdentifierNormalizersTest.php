<?php

declare(strict_types = 1);

namespace Tests\Feature\Identifiers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;
use SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormalizer;
use SineMacula\Laravel\Authentication\Identifiers\EmailNormalizer;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use Tests\TestCase;

/**
 * Feature tests for the identifier normaliser registry resolved from the
 * container over `authentication.identifiers.normalizers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierNormalizers::class)]
final class IdentifierNormalizersTest extends TestCase
{
    /**
     * The registry is one instance for the application, and out of the box it
     * knows only the email and E.164 phone normalisers.
     *
     * @return void
     */
    public function testShipsTheEmailAndPhoneNormalizersAsASingleton(): void
    {
        $registry = $this->registry();

        self::assertSame($registry, $this->registry());
        self::assertTrue($registry->has('email'));
        self::assertTrue($registry->has('phone'));
        self::assertFalse($registry->has('member_number'));
        self::assertFalse($registry->has('Email'));
        self::assertInstanceOf(EmailNormalizer::class, $registry->get('email'));
        self::assertInstanceOf(E164PhoneNormalizer::class, $registry->get('phone'));
        self::assertSame(['email', 'phone'], $registry->types());
    }

    /**
     * An application registers a normaliser for another type under a container
     * abstract of its own, resolved through the container.
     *
     * @return void
     */
    public function testRegistersApplicationNormalizersThroughTheContainer(): void
    {
        $digits = new class implements IdentifierNormalizer {
            /**
             * Keep only the digits.
             *
             * @param  string  $identifier
             * @return ?string
             */
            #[\Override]
            public function normalize(#[\SensitiveParameter] string $identifier): ?string
            {
                $digits = preg_replace('/\D+/', '', $identifier);

                return $digits === '' ? null : $digits;
            }
        };

        $this->app?->instance('normalizers.digits', $digits);

        config()->set('authentication.identifiers.normalizers.member_number', 'normalizers.digits');

        self::assertTrue($this->registry()->has('member_number'));
        self::assertSame(['email', 'phone', 'member_number'], $this->registry()->types());
        self::assertSame($digits, $this->registry()->get('member_number'));
        self::assertSame('0042', $this->registry()->get('member_number')->normalize('No. 00-42'));
    }

    /**
     * Asking for a type nothing is registered for is a misconfiguration.
     *
     * @return void
     */
    public function testUnknownTypeIsReported(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No identifier normaliser is registered for [member_number]: add it to `authentication.identifiers.normalizers`.');

        $this->registry()->get('member_number');
    }

    /**
     * An abstract that does not resolve to a normaliser is reported, naming the
     * type, the abstract and what it resolved to.
     *
     * @return void
     */
    public function testAbstractThatIsNotANormalizerIsReported(): void
    {
        config()->set('authentication.identifiers.normalizers.email', \stdClass::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The identifier normaliser for [email], [stdClass], resolved to [stdClass] instead of [' . IdentifierNormalizer::class . '].');

        $this->registry()->get('email');
    }

    /**
     * Malformed normaliser maps.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedMaps(): iterable
    {
        $map   = '`authentication.identifiers.normalizers` must be an array of identifier types to normaliser classes.';
        $entry = '`authentication.identifiers.normalizers` must map identifier types (lower-case letters, digits and underscores) to normaliser classes.';

        yield from [
            'missing'           => [null, $map],
            'a string'          => [EmailNormalizer::class, $map],
            'a list'            => [[EmailNormalizer::class], $entry],
            'upper-case type'   => [['Email' => EmailNormalizer::class], $entry],
            'type with newline' => [["email\n" => EmailNormalizer::class], $entry],
            'empty abstract'    => [['email' => ''], $entry],
            'instance abstract' => [['email' => new EmailNormalizer], $entry],
        ];
    }

    /**
     * A malformed map fails closed on every question, rather than leaving
     * identifiers as given.
     *
     * @param  mixed  $map
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedMaps')]
    public function testMalformedMapFailsClosed(mixed $map, string $message): void
    {
        config()->set('authentication.identifiers.normalizers', $map);

        $questions = [
            fn (): bool => $this->registry()->has('email'),
            fn (): IdentifierNormalizer => $this->registry()->get('email'),
            fn (): array => $this->registry()->types(),
        ];

        foreach ($questions as $question) {
            try {
                $question();
                self::fail('Expected the registry to fail closed.');
            } catch (\InvalidArgumentException $e) {
                self::assertSame($message, $e->getMessage());
            }
        }
    }

    /**
     * The registry the container binds.
     *
     * @return \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers
     */
    private function registry(): IdentifierNormalizers
    {
        $registry = $this->app?->make(IdentifierNormalizers::class);

        self::assertInstanceOf(IdentifierNormalizers::class, $registry);

        return $registry;
    }
}
