<?php

declare(strict_types = 1);

namespace Tests\Feature\Casts;

use Illuminate\Database\Eloquent\Casts\AsStringable;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use Tests\Integration\Fixtures\NormalisedEmailIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubReversingNormaliser;

/**
 * Feature tests for the cast that designates an identity attribute as an
 * identifier of a type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NormalisedIdentifier::class)]
final class NormalisedIdentifierTest extends TestCase
{
    /**
     * `using()` builds the declaration Eloquent instantiates the cast from, and
     * refuses a type that is not a valid identifier type.
     *
     * @return void
     */
    public function testUsingBuildsTheCastDeclaration(): void
    {
        self::assertSame(NormalisedIdentifier::class . ':email', NormalisedIdentifier::using('email'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier type [E-mail] must be a lower-case letter');

        NormalisedIdentifier::using('E-mail');
    }

    /**
     * A declaration made with `using()` yields the cast for its type; any other
     * declaration yields none.
     *
     * @return void
     */
    public function testFromDeclarationRecognisesOnlyIdentifierCasts(): void
    {
        self::assertSame('phone', NormalisedIdentifier::fromDeclaration(NormalisedIdentifier::using('phone'))?->type);
        self::assertNull(NormalisedIdentifier::fromDeclaration(NormalisedIdentifier::class));
        self::assertNull(NormalisedIdentifier::fromDeclaration('string'));
        self::assertNull(NormalisedIdentifier::fromDeclaration(AsStringable::class));
        self::assertNull(NormalisedIdentifier::fromDeclaration(null));
        self::assertNull(NormalisedIdentifier::fromDeclaration(['email']));
        self::assertNull(NormalisedIdentifier::fromDeclaration('x' . NormalisedIdentifier::using('email')));
    }

    /**
     * A hand-written declaration with a malformed type is a misconfiguration,
     * reported when the cast is built.
     *
     * @return void
     */
    public function testMalformedDeclaredTypeIsReported(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier type [] must be a lower-case letter');

        NormalisedIdentifier::fromDeclaration(NormalisedIdentifier::class . ':');
    }

    /**
     * Setting the attribute stores its normal form, by assignment and by mass
     * assignment, and `null` stays `null`.
     *
     * @return void
     */
    public function testSettingStoresTheNormalForm(): void
    {
        $identity        = new NormalisedEmailIdentity;
        $identity->email = '  Ben@Example.COM ';

        self::assertSame('ben@example.com', $identity->email);
        self::assertSame('ben@example.com', $identity->getAttributes()['email']);

        $filled = new NormalisedEmailIdentity(['email' => Str::of('ADA@Example.org')]);

        self::assertSame('ada@example.org', $filled->getAttributes()['email']);

        $identity->email = null;

        self::assertNull($identity->getAttributes()['email']);
    }

    /**
     * Reading returns the stored value as it is, so a row written before the
     * cast was added reads back unchanged until it is normalised.
     *
     * @return void
     */
    public function testReadingReturnsTheStoredValue(): void
    {
        $identity = (new NormalisedEmailIdentity)->newFromBuilder(['email' => 'Legacy@Example.COM']);

        self::assertSame('Legacy@Example.COM', $identity->email);
    }

    /**
     * Values the cast refuses to store.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'blank'         => ['   '],
            'invalid UTF-8' => ["ben\xC3\x28@example.com"],
            'an integer'    => [42],
            'an array'      => [['ben@example.com']],
        ];
    }

    /**
     * A value that cannot be an identifier of the type is refused, with a
     * message that names the attribute and model but never the value.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesValuesThatCannotBeAnIdentifier(mixed $value): void
    {
        $identity = new NormalisedEmailIdentity;

        $this->assertRefused(
            'Cannot set `email` on ' . NormalisedEmailIdentity::class . ': the value is not a valid `email` identifier.',
            static fn (): mixed => $identity->setAttribute('email', $value),
        );

        self::assertArrayNotHasKey('email', $identity->getAttributes());
    }

    /**
     * The cast uses whatever normaliser the application registers for its type.
     *
     * @return void
     */
    public function testNormalisesWithTheRegisteredNormaliser(): void
    {
        config()->set('authentication.identifiers.normalisers.email', StubReversingNormaliser::class);

        self::assertSame('moc.elpmaxe@neb', (new NormalisedIdentifier('email'))->normalise('ben@example.com'));
    }

    /**
     * Assert the callback throws an `InvalidArgumentException` with exactly the
     * given message.
     *
     * @param  string  $message
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function assertRefused(string $message, \Closure $callback): void
    {
        try {
            $callback();
        } catch (\InvalidArgumentException $e) {
            self::assertSame($message, $e->getMessage());

            return;
        }

        self::fail('Expected the cast to refuse the value.');
    }
}
