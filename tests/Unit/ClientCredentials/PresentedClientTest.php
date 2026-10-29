<?php

declare(strict_types = 1);

namespace Tests\Unit\ClientCredentials;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for what a client credentials token request presented: the client
 * id events may report is never a secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PresentedClient::class)]
final class PresentedClientTest extends TestCase
{
    /** @var string A secret in form. */
    private const string SECRET = 'Abcdefghij0123456789Abcdefghij0123456789';

    /**
     * Rows of `[client id presented, client id reported]`.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideClientIds(): iterable
    {
        yield from [
            'a public part'              => ['ak_abcdefghijklmnop', 'ak_abcdefghijklmnop'],
            'an unknown public part'     => ['ak_zzzzzzzzzzzzzzzz', 'ak_zzzzzzzzzzzzzzzz'],
            'the whole key'              => ['ak_abcdefghijklmnop_' . self::SECRET, null],
            'the secret, swapped for it' => [self::SECRET, null],
            'anything else'              => ['client', null],
        ];
    }

    /**
     * The client id is reported as given only when it is an API key's public
     * part in form, so a key or a secret sent as the id is never reported.
     *
     * @param  string  $clientId
     * @param  ?string  $reported
     * @return void
     */
    #[DataProvider('provideClientIds')]
    public function testReportsOnlyAClientIdInForm(string $clientId, ?string $reported): void
    {
        self::assertSame($reported, (new PresentedClient($clientId, 'secret', null, false))->reportedId());
    }

    /**
     * The secret is handed over by `clientSecret()` alone: no dump of what was
     * presented shows it, and serialising it throws.
     *
     * @return void
     */
    public function testTheSecretIsShownByNoDump(): void
    {
        $presented = new PresentedClient('ak_abcdefghijklmnop', self::SECRET, 'read', true);

        self::assertSame(self::SECRET, $presented->clientSecret());

        foreach ([(string) (new CliDumper)->dump((new VarCloner)->cloneVar($presented), true), print_r($presented, true), var_export($presented, true)] as $dumped) {
            self::assertStringNotContainsString(self::SECRET, $dumped);
            self::assertStringContainsString('ak_abcdefghijklmnop', $dumped);
        }

        $this->expectExceptionMessage('Serialization of \'SensitiveParameterValue\' is not allowed');

        serialize($presented);
    }
}
