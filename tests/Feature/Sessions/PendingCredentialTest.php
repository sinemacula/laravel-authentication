<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingCredential;
use Tests\TestCase;

/**
 * Feature tests for the helper a controller reads a request's pending
 * credential with: the configured body field alone, as a secret, refused as
 * `pending_invalid` when it is not a non-empty string, and absent when the body
 * has no such field.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingCredential::class)]
final class PendingCredentialTest extends TestCase
{
    /**
     * Rows of `[the request, what is read]`: the pending credential from the
     * JSON or form body field, a field that is not a non-empty string, and a
     * request whose body has no such field, the query string and a header never
     * read.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|string|null}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function providePendingCredentials(): iterable
    {
        $json = static fn (string $content): \Closure => static fn (): Request => Request::create(
            '/sign-in/factor',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: $content,
        );

        yield 'a JSON body' => [$json('{"pending_credential":"1.pending"}'), '1.pending'];
        yield 'a form body' => [static fn (): Request => Request::create('/sign-in/factor', 'POST', ['pending_credential' => '1.pending']), '1.pending'];
        yield 'an empty string' => [$json('{"pending_credential":""}'), FailureReason::PENDING_INVALID];
        yield 'a number' => [$json('{"pending_credential":1}'), FailureReason::PENDING_INVALID];
        yield 'a null' => [$json('{"pending_credential":null}'), FailureReason::PENDING_INVALID];
        yield 'an array' => [static fn (): Request => Request::create('/sign-in/factor', 'POST', ['pending_credential' => ['1.pending']]), FailureReason::PENDING_INVALID];
        yield 'no field' => [$json('{"code":"123456"}'), null];
        yield 'the query string' => [static fn (): Request => Request::create('/sign-in/factor?pending_credential=1.pending', 'POST'), null];
        yield 'a GET form' => [static fn (): Request => Request::create('/sign-in/factor', 'GET', ['pending_credential' => '1.pending']), null];
        yield 'a header' => [static fn (): Request => Request::create('/sign-in/factor', 'POST', server: ['HTTP_PENDING_CREDENTIAL' => '1.pending']), null];
    }

    /**
     * `extract()` reads the pending credential a request presents from the body
     * field alone: the credential as a secret, `pending_invalid` for a field
     * that is not a non-empty string, `null` when the body has no such field.
     * It reports nothing.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|string|null  $expected
     * @return void
     */
    #[DataProvider('providePendingCredentials')]
    public function testTheBodyFieldAloneIsRead(\Closure $request, FailureReason|string|null $expected): void
    {
        Event::fake();

        $credential = PendingCredential::extract($request());

        if (is_string($expected)) {
            self::assertInstanceOf(Secret::class, $credential);
            self::assertSame($expected, $credential->reveal());
        } else {
            self::assertSame($expected, $credential);
        }

        Event::assertNothingDispatched();
    }

    /**
     * `extract()` reads the field the configuration names, and refuses a name
     * PHP would file under another key.
     *
     * @return void
     */
    public function testTheConfiguredFieldIsRead(): void
    {
        $request = Request::create('/sign-in/factor', 'POST', ['pending_credential' => 'default', 'pending' => 'configured']);

        config()->set('authentication.session.pending_credential_field', 'pending');

        $credential = PendingCredential::extract($request);

        self::assertInstanceOf(Secret::class, $credential);
        self::assertSame('configured', $credential->reveal());

        config()->set('authentication.session.pending_credential_field', 'pending.credential');

        $this->expectException(\InvalidArgumentException::class);

        PendingCredential::extract($request);
    }
}
