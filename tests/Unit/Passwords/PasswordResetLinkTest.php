<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the password reset link a sender is given: it hands the token
 * to the sender and to nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordResetLink::class)]
final class PasswordResetLinkTest extends TestCase
{
    /**
     * The link carries its guard, type, destination, expiry and identity, and
     * the token through `token()`; no dump shows the token (Laravel's
     * VarDumper, `print_r`, `var_export`), `json_encode()` leaves it out,
     * serialising throws, and the constructor's parameter is sensitive.
     *
     * @return void
     */
    public function testTheTokenIsShownByNoDump(): void
    {
        $token     = str_repeat('Tk_-', 10) . 'abc';
        $expiresAt = CarbonImmutable::createStrict(2026, 10, 29, 10, 30, 0);
        $identity  = new PlainIdentityFixture(7);
        $link      = new PasswordResetLink('web', 'email', 'ada@example.test', $token, $expiresAt, $identity);

        self::assertSame(['web', 'email', 'ada@example.test', $token], [$link->guard, $link->type, $link->identifier, $link->token()]);
        self::assertSame([$expiresAt, $identity], [$link->expiresAt, $link->identity]);

        $dumps = [
            (string) (new CliDumper)->dump((new VarCloner)->cloneVar($link), true),
            print_r($link, true),
            var_export($link, true),
            (string) json_encode($link),
        ];

        foreach ($dumps as $dumped) {
            self::assertStringNotContainsString($token, $dumped);
            self::assertStringContainsString('ada@example.test', $dumped);
        }

        foreach (['identifier', 'token'] as $name) {
            self::assertNotSame([], (new \ReflectionParameter([PasswordResetLink::class, '__construct'], $name))->getAttributes(\SensitiveParameter::class));
        }

        $this->expectExceptionMessage('Serialization of \'SensitiveParameterValue\' is not allowed');

        serialize($link);
    }
}
