<?php

declare(strict_types = 1);

namespace Tests\Feature\Identifiers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser;
use SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormaliser;
use SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use Tests\TestCase;

/**
 * Feature tests for the identifier normaliser registry resolved from the
 * container over `authentication.identifiers.normalisers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierNormalisers::class)]
final class IdentifierNormalisersTest extends TestCase
{
    /**
     * The registry is one instance for the application, and out of the box it
     * knows only the email and E.164 phone normalisers.
     *
     * @return void
     */
    public function testShipsTheEmailAndPhoneNormalisersAsASingleton(): void
    {
        $registry = $this->registry();

        self::assertSame($registry, $this->registry());
        self::assertTrue($registry->has('email'));
        self::assertTrue($registry->has('phone'));
        self::assertFalse($registry->has('member_number'));
        self::assertFalse($registry->has('Email'));
        self::assertInstanceOf(EmailNormaliser::class, $registry->get('email'));
        self::assertInstanceOf(E164PhoneNormaliser::class, $registry->get('phone'));
    }

    /**
     * An application registers a normaliser for another type under a container
     * abstract of its own, resolved through the container.
     *
     * @return void
     */
    public function testRegistersApplicationNormalisersThroughTheContainer(): void
    {
        $digits = new class implements IdentifierNormaliser {
            /**
             * Keep only the digits.
             *
             * @param  string  $identifier
             * @return ?string
             */
            #[\Override]
            public function normalise(#[\SensitiveParameter] string $identifier): ?string
            {
                $digits = preg_replace('/\D+/', '', $identifier);

                return $digits === '' ? null : $digits;
            }
        };

        $this->app?->instance('normalisers.digits', $digits);

        config()->set('authentication.identifiers.normalisers.member_number', 'normalisers.digits');

        self::assertTrue($this->registry()->has('member_number'));
        self::assertSame($digits, $this->registry()->get('member_number'));
        self::assertSame('0042', $this->registry()->get('member_number')->normalise('No. 00-42'));
    }

    /**
     * Asking for a type nothing is registered for is a misconfiguration.
     *
     * @return void
     */
    public function testUnknownTypeIsReported(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No identifier normaliser is registered for [member_number]: add it to `authentication.identifiers.normalisers`.');

        $this->registry()->get('member_number');
    }

    /**
     * An abstract that does not resolve to a normaliser is reported, naming the
     * type, the abstract and what it resolved to.
     *
     * @return void
     */
    public function testAbstractThatIsNotANormaliserIsReported(): void
    {
        config()->set('authentication.identifiers.normalisers.email', \stdClass::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The identifier normaliser for [email], [stdClass], resolved to [stdClass] instead of [' . IdentifierNormaliser::class . '].');

        $this->registry()->get('email');
    }

    /**
     * Malformed normaliser maps.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedMaps(): iterable
    {
        $map   = '`authentication.identifiers.normalisers` must be an array of identifier types to normaliser classes.';
        $entry = '`authentication.identifiers.normalisers` must map identifier types (lower-case letters, digits and underscores) to normaliser classes.';

        yield from [
            'missing'           => [null, $map],
            'a string'          => [EmailNormaliser::class, $map],
            'a list'            => [[EmailNormaliser::class], $entry],
            'upper-case type'   => [['Email' => EmailNormaliser::class], $entry],
            'type with newline' => [["email\n" => EmailNormaliser::class], $entry],
            'empty abstract'    => [['email' => ''], $entry],
            'instance abstract' => [['email' => new EmailNormaliser], $entry],
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
        config()->set('authentication.identifiers.normalisers', $map);

        foreach ([fn (): bool => $this->registry()->has('email'), fn (): IdentifierNormaliser => $this->registry()->get('email')] as $question) {
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
     * @return \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers
     */
    private function registry(): IdentifierNormalisers
    {
        $registry = $this->app?->make(IdentifierNormalisers::class);

        self::assertInstanceOf(IdentifierNormalisers::class, $registry);

        return $registry;
    }
}
