<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ConsumerMessages;

/**
 * Unit tests for translating the messages the package answers a client with.
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
     * The messages are Laravel's own English text, so Laravel's translations
     * apply.
     *
     * @return void
     */
    public function testTheMessagesAreLaravelsEnglishText(): void
    {
        self::assertSame('Unauthenticated.', ConsumerMessages::UNAUTHENTICATED);
        self::assertSame('Too Many Attempts.', ConsumerMessages::TOO_MANY_ATTEMPTS);
    }

    /**
     * A message is translated by its JSON line in the current locale, if it has
     * one.
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
     * A message for which the translator answers with a whole file is kept as
     * it is.
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
     * The constructor is private; reflection invokes it for coverage.
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
     * An English translator with a French JSON line and an `auth` translation
     * file.
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
