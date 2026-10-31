<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ConsumerMessages;

/**
 * Unit tests for the translation of the messages the package answers a client
 * with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsumerMessages::class)]
final class ConsumerMessagesTest extends TestCase
{
    /**
     * The messages are the English text Laravel itself answers with, so an
     * application translating Laravel's translates the package's.
     *
     * @return void
     */
    public function testTheMessagesAreLaravelsEnglishText(): void
    {
        self::assertSame('Unauthenticated.', ConsumerMessages::UNAUTHENTICATED);
        self::assertSame('Too Many Attempts.', ConsumerMessages::TOO_MANY_ATTEMPTS);
    }

    /**
     * A message is translated by its JSON line in the current locale, and kept
     * as it is in a locale without one.
     *
     * @return void
     */
    public function testTranslatesByTheJsonLineOfTheLocale(): void
    {
        $translator = self::translator();

        $translator->setLocale('fr');

        self::assertSame('Trop de tentatives.', ConsumerMessages::translate($translator, ConsumerMessages::TOO_MANY_ATTEMPTS));
        self::assertSame(ConsumerMessages::UNAUTHENTICATED, ConsumerMessages::translate($translator, ConsumerMessages::UNAUTHENTICATED));

        $translator->setLocale('de');

        self::assertSame(ConsumerMessages::TOO_MANY_ATTEMPTS, ConsumerMessages::translate($translator, ConsumerMessages::TOO_MANY_ATTEMPTS));
    }

    /**
     * A message naming a translation file, for which the translator answers
     * with the whole file, is kept as it is.
     *
     * @return void
     */
    public function testKeepsAMessageTheTranslatorAnswersWithAFile(): void
    {
        $translator = self::translator();

        self::assertSame(['failed' => 'These credentials do not match our records.'], $translator->get('auth'));
        self::assertSame('auth', ConsumerMessages::translate($translator, 'auth'));
    }

    /**
     * `ConsumerMessages` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ConsumerMessages::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * A translator in English with a French JSON line for `Too Many
     * Attempts.` and an `auth` translation file.
     *
     * @return \Illuminate\Translation\Translator
     */
    private static function translator(): Translator
    {
        $loader = new ArrayLoader;

        $loader->addMessages('fr', '*', ['Too Many Attempts.' => 'Trop de tentatives.'], '*');
        $loader->addMessages('en', 'auth', ['failed' => 'These credentials do not match our records.']);

        return new Translator($loader, 'en');
    }
}
