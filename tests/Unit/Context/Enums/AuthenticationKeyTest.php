<?php

declare(strict_types = 1);

namespace Tests\Unit\Context\Enums;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\Enums\AuthenticationKey;
use SineMacula\Laravel\Authentication\Context\Enums\ContextKeyType;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;

/**
 * Unit tests for the `AuthenticationKey` and `ContextKeyType` enums.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationKey::class)]
#[CoversClass(ContextKeyType::class)]
final class AuthenticationKeyTest extends TestCase
{
    /**
     * The cases are the context's own keys, in the order it gives them.
     *
     * @return void
     */
    public function testTheCasesAreTheKeysTheContextGives(): void
    {
        $keys = array_map(
            static fn (string $key): string => AuthenticationContext::NAMESPACE . '.' . $key,
            array_keys(self::context()->toArray()[AuthenticationContext::NAMESPACE]),
        );

        self::assertSame($keys, array_column(AuthenticationKey::cases(), 'value'));
    }

    /**
     * Each key is read from the context by its case's value.
     *
     * @return void
     */
    public function testEachCaseReadsItsKey(): void
    {
        $context = self::context();

        foreach (AuthenticationKey::cases() as $key) {
            self::assertTrue($context->has($key->value), $key->value);
        }

        self::assertSame(1775476800, $context->get(AuthenticationKey::AUTH_TIME->value));
    }

    /**
     * Each value the context gives is of its key's declared type.
     *
     * @return void
     */
    public function testEachValueIsOfItsDeclaredType(): void
    {
        $context = self::context();

        foreach (AuthenticationKey::cases() as $key) {
            self::assertTrue(self::isOfType($context->get($key->value), $key->type()), $key->value);
        }
    }

    /**
     * The types are the key types an authorisation policy declares, by stable
     * names.
     *
     * @return void
     */
    public function testTheTypesHaveStableNames(): void
    {
        self::assertSame(['string', 'list', 'number', 'bool', 'ip', 'time'], array_column(ContextKeyType::cases(), 'value'));
    }

    /**
     * Each key has its documented type, `auth_time` an instant and
     * `seconds_since_step_up` a number.
     *
     * @return void
     */
    public function testEachKeyHasItsDocumentedType(): void
    {
        $types = [];

        foreach (AuthenticationKey::cases() as $key) {
            $types[$key->value] = $key->type()->value;
        }

        self::assertSame([
            'authentication.subject_type'          => 'string',
            'authentication.identity_type'         => 'string',
            'authentication.identity_id'           => 'string',
            'authentication.principal_type'        => 'string',
            'authentication.principal_id'          => 'string',
            'authentication.tenant_type'           => 'string',
            'authentication.tenant_id'             => 'string',
            'authentication.application'           => 'string',
            'authentication.session_id'            => 'string',
            'authentication.amr'                   => 'list',
            'authentication.auth_time'             => 'time',
            'authentication.mfa'                   => 'bool',
            'authentication.recovery_code'         => 'bool',
            'authentication.multifactor'           => 'bool',
            'authentication.seconds_since_step_up' => 'number',
            'authentication.credential'            => 'string',
            'authentication.scopes'                => 'list',
            'authentication.ip'                    => 'ip',
        ], $types);
    }

    /**
     * Whether the value is of the type.
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\Authentication\Context\Enums\ContextKeyType  $type
     * @return bool
     */
    private static function isOfType(mixed $value, ContextKeyType $type): bool
    {
        return match ($type) {
            ContextKeyType::STRING                       => is_string($value),
            ContextKeyType::LIST                         => is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value,
            ContextKeyType::NUMBER, ContextKeyType::TIME => is_int($value),
            ContextKeyType::BOOL                         => is_bool($value),
            ContextKeyType::IP                           => filter_var($value, FILTER_VALIDATE_IP) !== false,
        };
    }

    /**
     * A context with every key set, so none is `null`.
     *
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     */
    private static function context(): AuthenticationContext
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
            CredentialKind::CLIENT_CREDENTIALS,
            ['orders:read'],
            '203.0.113.7',
        );
    }
}
