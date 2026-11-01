<?php

declare(strict_types = 1);

namespace Tests\Feature\Casts;

use Illuminate\Database\Eloquent\Casts\AsStringable;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use Tests\Integration\Fixtures\NormalizedEmailIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubReversingNormalizer;

/**
 * Feature tests for the cast that designates an identity attribute as an
 * identifier of a type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NormalizedIdentifier::class)]
final class NormalizedIdentifierTest extends TestCase
{
    /**
     * `using()` builds the declaration Eloquent instantiates the cast from, and
     * refuses a type that is not a valid identifier type.
     *
     * @return void
     */
    public function testUsingBuildsTheCastDeclaration(): void
    {
        self::assertSame(NormalizedIdentifier::class . ':email', NormalizedIdentifier::using('email'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier type [E-mail] must be a lower-case letter');

        NormalizedIdentifier::using('E-mail');
    }

    /**
     * A declaration made with `using()` yields the cast for its type; any other
     * declaration yields none.
     *
     * @return void
     */
    public function testFromDeclarationRecognizesOnlyIdentifierCasts(): void
    {
        self::assertSame('phone', NormalizedIdentifier::fromDeclaration(NormalizedIdentifier::using('phone'))?->type);
        self::assertNull(NormalizedIdentifier::fromDeclaration(NormalizedIdentifier::class));
        self::assertNull(NormalizedIdentifier::fromDeclaration('string'));
        self::assertNull(NormalizedIdentifier::fromDeclaration(AsStringable::class));
        self::assertNull(NormalizedIdentifier::fromDeclaration(null));
        self::assertNull(NormalizedIdentifier::fromDeclaration(['email']));
        self::assertNull(NormalizedIdentifier::fromDeclaration('x' . NormalizedIdentifier::using('email')));
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

        NormalizedIdentifier::fromDeclaration(NormalizedIdentifier::class . ':');
    }

    /**
     * Setting the attribute stores its normal form, by assignment and by mass
     * assignment, and `null` stays `null`.
     *
     * @return void
     */
    public function testSettingStoresTheNormalForm(): void
    {
        $identity        = new NormalizedEmailIdentity;
        $identity->email = '  Ben@Example.COM ';

        self::assertSame('ben@example.com', $identity->email);
        self::assertSame('ben@example.com', $identity->getAttributes()['email']);

        $filled = new NormalizedEmailIdentity(['email' => Str::of('ADA@Example.org')]);

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
        $identity = (new NormalizedEmailIdentity)->newFromBuilder(['email' => 'Legacy@Example.COM']);

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
        $identity = new NormalizedEmailIdentity;

        $this->assertRefused(
            'Cannot set `email` on ' . NormalizedEmailIdentity::class . ': the value is not a valid `email` identifier.',
            static fn (): mixed => $identity->setAttribute('email', $value),
        );

        self::assertArrayNotHasKey('email', $identity->getAttributes());
    }

    /**
     * The cast uses whatever normaliser the application registers for its type.
     *
     * @return void
     */
    public function testNormalizesWithTheRegisteredNormalizer(): void
    {
        config()->set('authentication.identifiers.normalizers.email', StubReversingNormalizer::class);

        self::assertSame('moc.elpmaxe@neb', (new NormalizedIdentifier('email'))->normalize('ben@example.com'));
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
