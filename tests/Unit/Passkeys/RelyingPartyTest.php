<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\RelyingParty;

/**
 * Unit tests for a guard's relying party: the guard's `passkeys` block over the
 * package's defaults, and the validation that fails closed naming the guard and
 * the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RelyingParty::class)]
final class RelyingPartyTest extends TestCase
{
    /** @var string The message for origins that are not exact secure origins on the id. */
    private const string ORIGINS_MESSAGE = 'Passkey relying party `origins` for guard [web] must be a non-empty list of exact lower-case origins, each'
        . ' `https://host[:port]` (or `http://localhost[:port]`) on the relying party id or a subdomain of it:'
        . ' set `authentication.passkeys.relying_party.origins` or the guard\'s `passkeys.origins` override.';

    /**
     * The package's relying party applies to a guard that sets none, with the
     * application's name when it names none.
     *
     * @return void
     */
    public function testThePackageDefaultsApplyToAGuardWithoutABlock(): void
    {
        $rp = RelyingParty::forGuard('web', self::config(['id' => 'example.test', 'name' => null, 'origins' => ['https://example.test']]));

        self::assertSame(['web', 'example.test', 'App', ['https://example.test']], [$rp->guard, $rp->id, $rp->name, $rp->origins]);
    }

    /**
     * Each key the guard's block sets wins over the package's, and the others
     * are the package's.
     *
     * @return void
     */
    public function testEachKeyOfTheGuardsBlockWins(): void
    {
        $package = ['id' => 'example.test', 'name' => 'Package', 'origins' => ['https://example.test']];
        $config  = self::config($package, ['id' => 'admin.example.test', 'origins' => ['https://admin.example.test:8443']]);
        $rp      = RelyingParty::forGuard('web', $config);

        self::assertSame(['admin.example.test', 'Package', ['https://admin.example.test:8443']], [$rp->id, $rp->name, $rp->origins]);

        $config->set('auth.guards.web.passkeys.name', 'Admin');

        self::assertSame('Admin', RelyingParty::forGuard('web', $config)->name);
    }

    /**
     * Rows of `[id, origins]`: valid relying parties.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideValidRelyingParties(): iterable
    {
        yield from [
            'the id itself'               => ['example.test', ['https://example.test']],
            'subdomains of the id'        => ['example.test', ['https://app.example.test', 'https://a.b.example.test']],
            'a port'                      => ['example.test', ['https://example.test:8443', 'https://example.test:65535', 'https://example.test:1']],
            'localhost over http'         => ['localhost', ['http://localhost', 'http://localhost:8000', 'https://localhost']],
            'a single-label host'         => ['intranet', ['https://intranet']],
            'labels with digits, hyphens' => ['my-app2.example.test', ['https://my-app2.example.test']],
        ];
    }

    /**
     * Valid ids and origins are accepted as given.
     *
     * @param  string  $id
     * @param  list<string>  $origins
     * @return void
     */
    #[DataProvider('provideValidRelyingParties')]
    public function testValidRelyingPartiesAreAccepted(string $id, array $origins): void
    {
        $rp = RelyingParty::forGuard('web', self::config(['id' => $id, 'name' => 'App', 'origins' => $origins]));

        self::assertSame([$id, $origins], [$rp->id, $rp->origins]);
    }

    /**
     * Rows of `[id]`: ids that are not a lower-case host name.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideInvalidIds(): iterable
    {
        yield from [
            'none'                => [null],
            'empty'               => [''],
            'not a string'        => [42],
            'upper case'          => ['Example.test'],
            'a trailing dot'      => ['example.test.'],
            'a leading hyphen'    => ['-example.test'],
            'a trailing hyphen'   => ['example-.test'],
            'an underscore'       => ['my_app.test'],
            'an empty label'      => ['example..test'],
            'an IPv4 address'     => ['127.0.0.1'],
            'an IPv6 address'     => ['::1'],
            'a scheme'            => ['https://example.test'],
            'a port'              => ['example.test:443'],
            'a label of 64 chars' => [str_repeat('a', 64) . '.test'],
            'over 253 chars'      => [implode('.', array_fill(0, 64, 'abc')) . '.test'],
        ];
    }

    /**
     * An id that is not a lower-case host name fails closed.
     *
     * @param  mixed  $id
     * @return void
     */
    #[DataProvider('provideInvalidIds')]
    public function testAnInvalidIdFailsClosed(mixed $id): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Passkey relying party `id` for guard [web] must be a lower-case host name, not an IP address:'
            . ' set `authentication.passkeys.relying_party.id` or the guard\'s `passkeys.id` override.');

        RelyingParty::forGuard('web', self::config(['id' => $id, 'name' => 'App', 'origins' => ['https://example.test']]));
    }

    /**
     * The longest host name a label pattern allows, 63 characters a label and
     * 253 in all, is accepted.
     *
     * @return void
     */
    public function testTheLongestHostNameIsAccepted(): void
    {
        $id = implode('.', [str_repeat('a', 63), str_repeat('b', 63), str_repeat('c', 63), str_repeat('d', 61)]);

        self::assertSame(253, strlen($id));
        self::assertSame($id, RelyingParty::forGuard('web', self::config(['id' => $id, 'name' => 'App', 'origins' => ["https://{$id}"]]))->id);
    }

    /**
     * Rows of `[name, application name]`: names that leave the relying party
     * without one.
     *
     * @return iterable<string, array{0: mixed, 1: mixed}>
     */
    public static function provideInvalidNames(): iterable
    {
        yield from [
            'none, and no application name' => [null, null],
            'none, and a blank app name'    => [null, '  '],
            'empty'                         => ['', 'App'],
            'blank'                         => [" \t", 'App'],
            'not a string'                  => [['App'], 'App'],
        ];
    }

    /**
     * A name that is missing, blank or not a string fails closed.
     *
     * @param  mixed  $name
     * @param  mixed  $appName
     * @return void
     */
    #[DataProvider('provideInvalidNames')]
    public function testAnInvalidNameFailsClosed(mixed $name, mixed $appName): void
    {
        $config = self::config(['id' => 'example.test', 'name' => $name, 'origins' => ['https://example.test']]);

        $config->set('app.name', $appName);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Passkey relying party `name` for guard [web] must be a non-empty string (or `app.name` set):');

        RelyingParty::forGuard('web', $config);
    }

    /**
     * Rows of `[origin]`: secure origins under the relying party id whose host
     * is not a valid host name.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOriginsWithInvalidHosts(): iterable
    {
        yield from [
            'an empty label'             => ['https://app..example.test'],
            'an underscore in the host'  => ['https://my_app.example.test'],
            'a hyphen ending a label'    => ['https://app-.example.test'],
            'a label over 63 characters' => ['https://' . str_repeat('a', 64) . '.example.test'],
        ];
    }

    /**
     * An origin under the relying party id fails closed when its host is not a
     * valid host name, though it ends in the id.
     *
     * @param  string  $origin
     * @return void
     */
    #[DataProvider('provideOriginsWithInvalidHosts')]
    public function testAnOriginWithAnInvalidHostFailsClosed(string $origin): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::ORIGINS_MESSAGE);

        RelyingParty::forGuard('web', self::config(['id' => 'example.test', 'name' => 'App', 'origins' => [$origin]]));
    }

    /**
     * Rows of `[origins]`: origin lists that are not exact, secure origins on
     * the relying party id.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideInvalidOrigins(): iterable
    {
        yield from [
            'none'                          => [null],
            'not a list'                    => ['https://example.test'],
            'empty'                         => [[]],
            'keyed'                         => [['web' => 'https://example.test']],
            'not a string'                  => [[443]],
            'http on a public host'         => [['http://example.test']],
            'http on a localhost subdomain' => [['http://app.localhost']],
            'another scheme'                => [['ftp://example.test']],
            'no scheme'                     => [['example.test']],
            'a trailing slash'              => [['https://example.test/']],
            'a path'                        => [['https://example.test/app']],
            'a query'                       => [['https://example.test?x=1']],
            'a fragment'                    => [['https://example.test#x']],
            'credentials'                   => [['https://user@example.test']],
            'upper case'                    => [['https://Example.test']],
            'another host'                  => [['https://other.test']],
            'a host that only ends alike'   => [['https://notexample.test']],
            'a parent of the id'            => [['https://test']],
            'port 0'                        => [['https://example.test:0']],
            'a port above 65535'            => [['https://example.test:65536']],
            'a port with a leading zero'    => [['https://example.test:0443']],
            'an empty port'                 => [['https://example.test:']],
            'one bad among good'            => [['https://example.test', 'https://evil.test']],
        ];
    }

    /**
     * Origins that are missing, not a list of exact secure origins, or not on
     * the relying party id fail closed.
     *
     * @param  mixed  $origins
     * @return void
     */
    #[DataProvider('provideInvalidOrigins')]
    public function testInvalidOriginsFailClosed(mixed $origins): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::ORIGINS_MESSAGE);

        RelyingParty::forGuard('web', self::config(['id' => 'example.test', 'name' => 'App', 'origins' => $origins]));
    }

    /**
     * Origins left out of both blocks fail closed.
     *
     * @return void
     */
    public function testMissingOriginsFailClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Passkey relying party `origins` for guard [web] must be');

        RelyingParty::forGuard('web', self::config(['id' => 'example.test']));
    }

    /**
     * A guard that is not configured fails closed.
     *
     * @return void
     */
    public function testAGuardThatIsNotConfiguredFailsClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [missing] is not configured.');

        RelyingParty::forGuard('missing', self::config(['id' => 'example.test', 'name' => 'App', 'origins' => ['https://example.test']]));
    }

    /**
     * Rows of `[package block, guard block, message]`: blocks that are not
     * arrays, or that set a key the relying party does not know.
     *
     * @return iterable<string, array{0: mixed, 1: mixed, 2: string}>
     */
    public static function provideMalformedBlocks(): iterable
    {
        $valid = ['id' => 'example.test', 'name' => 'App', 'origins' => ['https://example.test']];

        yield from [
            'a package block that is not an array' => ['example.test', null, 'Passkey configuration for guard [web]: `authentication.passkeys.relying_party` must be an array.'],
            'a guard block that is not an array'   => [$valid, 'example.test', 'Passkey configuration for guard [web]: the guard\'s `passkeys` overrides must be an array.'],
            'an unknown package key'               => [
                [...$valid, 'origin' => 'https://example.test'],
                null,
                'Passkey configuration for guard [web]: `authentication.passkeys.relying_party` has an unknown key `origin`.',
            ],
            'an unknown guard key' => [
                $valid,
                ['rp_id' => 'example.test'],
                'Passkey configuration for guard [web]: the guard\'s `passkeys` overrides has an unknown key `rp_id`.',
            ],
        ];
    }

    /**
     * A block that is not an array, or that sets an unknown key, fails closed
     * naming the guard, the block and the key.
     *
     * @param  mixed  $package
     * @param  mixed  $guard
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedBlocks')]
    public function testAMalformedBlockFailsClosed(mixed $package, mixed $guard, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        RelyingParty::forGuard('web', self::config($package, $guard));
    }

    /**
     * Configuration with the package's relying party block, a `web` guard and,
     * when given, its `passkeys` block.
     *
     * @param  mixed  $package
     * @param  mixed  $guard
     * @return \Illuminate\Config\Repository
     */
    private static function config(mixed $package, mixed $guard = null): Repository
    {
        $web = ['driver' => 'jwt'];

        if ($guard !== null) {
            $web['passkeys'] = $guard;
        }

        return new Repository([
            'app'            => ['name' => 'App'],
            'auth'           => ['guards' => ['web' => $web]],
            'authentication' => ['passkeys' => ['relying_party' => $package]],
        ]);
    }
}
