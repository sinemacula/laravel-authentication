<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Jwt\MachineTokens;

/**
 * Unit tests for how a non-human identity's tokens differ from a session's: no
 * session token, and the key and scopes a client credentials token carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MachineTokens::class)]
final class MachineTokensTest extends TestCase
{
    /** @var string An API key id. */
    private const string KEY_ID = '0195f4a2-7b1c-7000-8000-000000000001';

    /**
     * A machine is refused a session token; anyone else is not.
     *
     * @return void
     */
    public function testRefusesASessionTokenToAMachineOnly(): void
    {
        MachineTokens::refuseSession(false);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A non-human identity has no session: it gets access tokens only from a client credentials exchange.');

        MachineTokens::refuseSession(true);
    }

    /**
     * The claims of a client token are the key's id and its scopes, normalised
     * and space-separated; the id must be a UUID and every scope well-formed.
     *
     * @return void
     */
    public function testBuildsTheClaimsOfAClientToken(): void
    {
        self::assertSame(['cid' => self::KEY_ID, 'scope' => 'b a'], MachineTokens::claims(self::KEY_ID, ['b', 'a', 'b']));
        self::assertSame(['cid' => self::KEY_ID, 'scope' => ''], MachineTokens::claims(self::KEY_ID, []));

        try {
            MachineTokens::claims('key-1', []);

            self::fail('Expected a key id that is not a UUID to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Cannot issue a client credentials token without its `cid` claim: the API key id must be a UUID.', $exception->getMessage());
        }

        $this->expectException(InvalidScopeException::class);

        MachineTokens::claims(self::KEY_ID, ['a b']);
    }

    /**
     * Rows of `[claims, what they name]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array{0: string, 1: list<string>}|false|null}>
     */
    public static function provideClaims(): iterable
    {
        yield from [
            'no credential'      => [['sub' => '7'], null],
            'a null credential'  => [['cid' => null, 'scope' => 'a'], null],
            'key and scopes'     => [['cid' => self::KEY_ID, 'scope' => 'a b'], [self::KEY_ID, ['a', 'b']]],
            'key and no scope'   => [['cid' => self::KEY_ID, 'scope' => ''], [self::KEY_ID, []]],
            'a null device'      => [['cid' => self::KEY_ID, 'scope' => 'a', 'did' => null], [self::KEY_ID, ['a']]],
            'no scope'           => [['cid' => self::KEY_ID], false],
            'a non-string scope' => [['cid' => self::KEY_ID, 'scope' => 5], false],
            'a malformed scope'  => [['cid' => self::KEY_ID, 'scope' => ' a'], false],
            'not a uuid'         => [['cid' => 'key-1', 'scope' => 'a'], false],
            'a non-string key'   => [['cid' => 7, 'scope' => 'a'], false],
            'a device'           => [['cid' => self::KEY_ID, 'scope' => 'a', 'did' => 'd-1'], false],
        ];
    }

    /**
     * The key and scopes a token's claims name, none, or a malformed naming.
     *
     * @param  array<string, mixed>  $claims
     * @param  array{0: string, 1: list<string>}|false|null  $expected
     * @return void
     */
    #[DataProvider('provideClaims')]
    public function testReadsTheKeyAndScopesAClientTokenNames(array $claims, array|false|null $expected): void
    {
        self::assertSame($expected, MachineTokens::credential($claims));
    }

    /**
     * The class is a utility container only.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(MachineTokens::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(MachineTokens::class, $instance);
    }
}
