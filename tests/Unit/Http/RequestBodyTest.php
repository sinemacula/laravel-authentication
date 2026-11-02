<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\RequestBody;

/**
 * Unit tests for the body a credential is read from: the JSON body, or the form
 * body of a request that may have one, never the query string; and the field
 * names PHP keeps as they are in a form body.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestBody::class)]
final class RequestBodyTest extends TestCase
{
    /**
     * A JSON request's fields are its JSON body, whatever its method, and never
     * its query string.
     *
     * @return void
     */
    public function testAJsonRequestsFieldsAreItsJsonBody(): void
    {
        foreach (['POST', 'GET'] as $method) {

            $content = '{"credential":"from-the-body","nested":{"a":1}}';
            $request = Request::create('/refresh?credential=from-the-query', $method, server: ['CONTENT_TYPE' => 'application/json'], content: $content);

            self::assertSame(['credential' => 'from-the-body', 'nested' => ['a' => 1]], RequestBody::fields($request));
        }
    }

    /**
     * A form request's fields are its form body, for a method that may have
     * one, and never its query string.
     *
     * @return void
     */
    public function testAFormRequestsFieldsAreItsFormBody(): void
    {
        $request = Request::create('/refresh?credential=from-the-query', 'POST', ['credential' => 'from-the-body']);

        self::assertSame(['credential' => 'from-the-body'], RequestBody::fields($request));
    }

    /**
     * A form request of a method that has no body has no fields: what it
     * carries is its query string.
     *
     * @return void
     */
    public function testARequestOfAMethodWithoutABodyHasNoFields(): void
    {
        foreach (['GET', 'HEAD'] as $method) {
            self::assertSame([], RequestBody::fields(Request::create('/refresh', $method, ['credential' => 'from-the-query'])));
        }
    }

    /**
     * Rows of `[the name, whether PHP keeps it as it is in a form body]`.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideFieldNames(): iterable
    {
        yield 'a plain name' => ['refresh_token', true];
        yield 'a name with a dash and digits' => ['pending-credential-2', true];
        yield 'a dotted name, filed as `_`' => ['pending.credential', false];
        yield 'a name with a space, filed as `_`' => ['pending credential', false];
        yield 'a name with a tab' => ["pending\tcredential", false];
        yield 'a bracketed name, which nests' => ['pending[credential]', false];
        yield 'a closing bracket' => ['pending]', false];
        yield 'a control character' => ["pending\x00", false];
        yield 'the delete character' => ["pending\x7F", false];
        yield 'a trailing newline' => ["pending\n", false];
        yield 'an empty name' => ['', false];
        yield 'not a string' => [42, false];
        yield 'null' => [null, false];
    }

    /**
     * A field name is a string PHP files as it is in a form body: no
     * whitespace, `.`, bracket or control character.
     *
     * @param  mixed  $name
     * @param  bool  $kept
     * @return void
     */
    #[DataProvider('provideFieldNames')]
    public function testAFieldNameIsOnePhpKeepsAsItIs(mixed $name, bool $kept): void
    {
        self::assertSame($kept, RequestBody::isFieldName($name));
    }

    /**
     * The utility cannot be instantiated: its constructor is private.
     * Reflection invokes it so the line is covered while still documenting the
     * access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(RequestBody::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(RequestBody::class, $instance);
    }
}
