<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;

/**
 * Unit tests for the authentication context as a value: its keys as plain
 * values by namespace, the package's under `authentication`; a key read by
 * `namespace.key`, present even with a `null` value; and contributed keys
 * refused unless a contributor could have given them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContext::class)]
final class AuthenticationContextTest extends TestCase
{
    /**
     * The context gives the package's keys under `authentication`, the enums as
     * their values and `auth_time` as Unix seconds, then each contributor's
     * namespace as given.
     *
     * @return void
     */
    public function testTheKeysArePlainValuesByNamespace(): void
    {
        $context = self::context(['sso' => ['connection_id' => 'connection-7', 'provider_amr' => ['hwk', 'pin']], 'mfa' => ['factors' => 2]]);

        self::assertSame([
            'authentication' => [
                'subject_type'          => 'person',
                'identity_type'         => 'identity',
                'identity_id'           => '7',
                'principal_type'        => 'membership',
                'principal_id'          => '11',
                'tenant_type'           => 'tenant',
                'tenant_id'             => '3',
                'application'           => 'admin',
                'session_id'            => 'session-1',
                'amr'                   => ['pwd', 'otp', 'mfa'],
                'auth_time'             => 1775476800,
                'mfa'                   => true,
                'recovery_code'         => false,
                'multifactor'           => true,
                'seconds_since_step_up' => 30,
                'credential'            => 'access_token',
                'scopes'                => null,
                'ip'                    => '203.0.113.7',
            ],
            'sso' => ['connection_id' => 'connection-7', 'provider_amr' => ['hwk', 'pin']],
            'mfa' => ['factors' => 2],
        ], $context->toArray());
    }

    /**
     * A context with nothing known about the session, its proofs or the
     * credential gives `null`, an empty list and false for them.
     *
     * @return void
     */
    public function testAContextWithoutASessionOrCredentialGivesNullsAndFalse(): void
    {
        $context = new AuthenticationContext(SubjectType::MACHINE, 'machine', '9', 'machine', '9', null, null, 'm2m', null, [], null, false, false, false, null, null, [], null);

        self::assertSame([
            'subject_type'          => 'machine',
            'identity_type'         => 'machine',
            'identity_id'           => '9',
            'principal_type'        => 'machine',
            'principal_id'          => '9',
            'tenant_type'           => null,
            'tenant_id'             => null,
            'application'           => 'm2m',
            'session_id'            => null,
            'amr'                   => [],
            'auth_time'             => null,
            'mfa'                   => false,
            'recovery_code'         => false,
            'multifactor'           => false,
            'seconds_since_step_up' => null,
            'credential'            => null,
            'scopes'                => [],
            'ip'                    => null,
        ], $context->toArray()['authentication']);
        self::assertSame([], $context->contributed);
    }

    /**
     * A key is read by its namespace and name, the package's and a
     * contributor's alike; one held with a `null` value is present and reads
     * `null`, never the default; one not held reads the default.
     *
     * @return void
     */
    public function testAKeyIsReadByNamespaceAndName(): void
    {
        $context = self::context(['sso' => ['connection_id' => 'connection-7', 'link_id' => null]]);

        self::assertTrue($context->get('authentication.mfa'));
        self::assertSame('admin', $context->get('authentication.application'));
        self::assertSame(1775476800, $context->get('authentication.auth_time'));
        self::assertSame('connection-7', $context->get('sso.connection_id'));

        self::assertTrue($context->has('authentication.scopes'));
        self::assertNull($context->get('authentication.scopes', 'default'));
        self::assertTrue($context->has('sso.link_id'));
        self::assertNull($context->get('sso.link_id', 'default'));

        self::assertFalse($context->has('sso.tenant_id'));
        self::assertSame('default', $context->get('sso.tenant_id', 'default'));
        self::assertFalse($context->has('mfa.factors'));
        self::assertNull($context->get('mfa.factors'));
        self::assertFalse($context->has('authentication.password'));
    }

    /**
     * Rows of `[key]`: each not of the form `namespace.key`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedKeys(): iterable
    {
        yield 'a namespace alone' => ['authentication'];
        yield 'no namespace' => ['mfa'];
        yield 'two dots' => ['sso.connection.id'];
        yield 'empty' => [''];
    }

    /**
     * A key not of the form `namespace.key` is never held.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideMalformedKeys')]
    public function testAKeyNotOfTheFormNamespaceDotKeyIsNeverHeld(string $key): void
    {
        $context = self::context(['sso' => ['connection' => ['id' => 'connection-7']]]);

        self::assertFalse($context->has($key));
        self::assertSame('default', $context->get($key, 'default'));
    }

    /**
     * Keys a contributor may give are taken as given: lower-case names of up to
     * 64 characters, values `null`, scalars or arrays of them nested.
     *
     * @return void
     */
    public function testPlainContributedValuesAreTakenAsGiven(): void
    {
        $longest = 'k' . str_repeat('e_9', 21);
        $keys    = [
            'nothing' => null,
            'flag'    => false,
            'count'   => 3,
            'ratio'   => 0.5,
            'name'    => 'connection-7',
            'nested'  => ['list' => [1, 'two', null, [true]], 'empty' => []],
            $longest  => 'longest',
        ];

        self::assertSame($keys, self::context(['sso' => $keys])->contributed['sso']);
    }

    /**
     * Rows of `[contributed, message]`: contributed keys no contributor could
     * have given, and what the refusal says.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function provideRefusedContributions(): iterable
    {
        $object = new \stdClass;

        yield 'the package\'s namespace' => [['authentication' => ['mfa' => false]], 'The contributed namespace [authentication] is the package\'s own'];
        yield 'a malformed namespace' => [['Sso' => ['id' => 'a']], 'The contributed namespace [Sso] is the package\'s own'];
        yield 'a namespace that is a number' => [[7 => ['id' => 'a']], 'The contributed namespace [7] is the package\'s own'];
        yield 'keys that are not an array' => [['sso' => 'connection-7'], 'The keys contributed under [sso] must be an array.'];
        yield 'a key that is a number' => [['sso' => ['connection-7']], 'The key [0] contributed under [sso] must be a lower-case letter'];
        yield 'a key in upper case' => [['sso' => ['Id' => 'a']], 'The key [Id] contributed under [sso] must be a lower-case letter'];
        yield 'a key with a dot' => [['sso' => ['connection.id' => 'a']], 'The key [connection.id] contributed under [sso]'];
        yield 'a key too long' => [['sso' => ['k' . str_repeat('e', 64) => 'a']], 'contributed under [sso] must be a lower-case letter'];
        yield 'an object' => [['sso' => ['link' => $object]], 'The value of [sso.link] must be null, a scalar or an array of them'];
        yield 'an object nested' => [['sso' => ['links' => ['a', ['b' => $object]]]], 'The value of [sso.links] must be null, a scalar or an array of them'];
        yield 'an enum' => [['sso' => ['kind' => CredentialKind::API_KEY]], 'The value of [sso.kind] must be null'];
    }

    /**
     * Contributed keys no contributor could have given are refused, saying
     * which namespace and key.
     *
     * @param  array<array-key, mixed>  $contributed
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedContributions')]
    public function testContributedKeysNoContributorCouldGiveAreRefused(array $contributed, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::context($contributed);
    }

    /**
     * A resource is no plain value.
     *
     * @return void
     */
    public function testAResourceIsRefused(): void
    {
        $resource = fopen('php://memory', 'rb');

        try {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('The value of [sso.stream] must be null, a scalar or an array of them');

            self::context(['sso' => ['stream' => $resource]]);
        } finally {
            fclose($resource);
        }
    }

    /**
     * A person's context acting in a tenant, stepped up thirty seconds ago,
     * with the keys contributed given.
     *
     * @param  array<array-key, mixed>  $contributed
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     */
    private static function context(array $contributed = []): AuthenticationContext
    {
        return new AuthenticationContext(
            SubjectType::PERSON,
            'identity',
            '7',
            'membership',
            '11',
            'tenant',
            '3',
            'admin',
            'session-1',
            ['pwd', 'otp', 'mfa'],
            CarbonImmutable::createFromTimestamp(1775476800),
            true,
            false,
            true,
            30,
            CredentialKind::ACCESS_TOKEN,
            null,
            '203.0.113.7',
            $contributed,
        );
    }
}
