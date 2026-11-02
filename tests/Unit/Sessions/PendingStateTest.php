<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingState;
use Tests\Unit\Stubs\StubUncastSession;

/**
 * Unit tests for what every path that makes a session pending shares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingState::class)]
final class PendingStateTest extends TestCase
{
    /**
     * Rows of `[configured lifetime, seconds read]`.
     *
     * @return iterable<string, array{0: mixed, 1: int}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'unset' => [null, 300];
        yield 'the shortest' => [30, 30];
        yield 'the longest' => [3600, 3600];
        yield 'a digit string, as env() gives' => ['600', 600];
    }

    /**
     * The pending credential lives as long as the session configuration says,
     * five minutes when it says nothing, read from its own key.
     *
     * @param  mixed  $configured
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('provideLifetimes')]
    public function testThePendingCredentialLivesForTheConfiguredLifetime(mixed $configured, int $seconds): void
    {
        $config = new Repository($configured === null ? [] : ['authentication' => ['session' => ['pending_ttl_seconds' => $configured]]]);

        self::assertSame('authentication.session.pending_ttl_seconds', PendingState::TTL_KEY);
        self::assertSame($seconds, PendingState::ttlSeconds($config));
    }

    /**
     * Rows of `[configured lifetime]` outside 30 to 3600 seconds, or not an
     * integer.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedLifetimes(): iterable
    {
        yield 'too short' => [29];
        yield 'too long' => [3601];
        yield 'zero' => [0];
        yield 'negative' => [-300];
        yield 'padded digit string' => ['0300'];
        yield 'signed digit string' => ['+300'];
        yield 'decimal' => [300.0];
        yield 'trailing newline' => ["300\n"];
        yield 'null' => [null];
        yield 'words' => ['five minutes'];
        yield 'too long as a string' => ['3601'];
    }

    /**
     * A malformed lifetime fails closed when a session becomes pending, naming
     * the setting.
     *
     * @param  mixed  $configured
     * @return void
     */
    #[DataProvider('provideMalformedLifetimes')]
    public function testAMalformedLifetimeFailsClosed(mixed $configured): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.session.pending_ttl_seconds must be an integer from 30 to 3600.');

        PendingState::ttlSeconds(new Repository(['authentication' => ['session' => ['pending_ttl_seconds' => $configured]]]));
    }

    /**
     * Rows of `[configured field, field read]`.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideCredentialFields(): iterable
    {
        yield 'unset' => [null, 'pending_credential'];
        yield 'a field of its own' => ['pending', 'pending'];
        yield 'with dashes and digits' => ['x-pending-2', 'x-pending-2'];
    }

    /**
     * The pending credential is read from the configured body field,
     * `pending_credential` when the configuration names none, read from its own
     * key.
     *
     * @param  mixed  $configured
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideCredentialFields')]
    public function testThePendingCredentialIsReadFromTheConfiguredField(mixed $configured, string $field): void
    {
        $config = new Repository($configured === null ? [] : ['authentication' => ['session' => ['pending_credential_field' => $configured]]]);

        self::assertSame('authentication.session.pending_credential_field', PendingState::FIELD_KEY);
        self::assertSame($field, PendingState::credentialField($config));
    }

    /**
     * Rows of `[configured field]` PHP would file under another key in a form
     * body, or that are not a name.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedCredentialFields(): iterable
    {
        yield 'empty' => [''];
        yield 'dotted' => ['pending.credential'];
        yield 'spaced' => ['pending credential'];
        yield 'bracketed' => ['pending[credential]'];
        yield 'an opening bracket' => ['pending['];
        yield 'a tab' => ["pending\tcredential"];
        yield 'a trailing newline' => ["pending\n"];
        yield 'a control character' => ["pending\x00"];
        yield 'a delete character' => ["pending\x7F"];
        yield 'null' => [null];
        yield 'not a string' => [['pending']];
    }

    /**
     * A malformed field fails closed when a route reads the pending credential,
     * naming the setting.
     *
     * @param  mixed  $configured
     * @return void
     */
    #[DataProvider('provideMalformedCredentialFields')]
    public function testAMalformedCredentialFieldFailsClosed(mixed $configured): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.session.pending_credential_field must be a field name without `.`, spaces or brackets.');

        PendingState::credentialField(new Repository(['authentication' => ['session' => ['pending_credential_field' => $configured]]]));
    }

    /**
     * The credential expires its lifetime later, or at the session's absolute
     * deadline when that comes first.
     *
     * @return void
     */
    public function testTheExpiryNeverPassesTheAbsoluteDeadline(): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00');

        self::assertSame('2026-04-06 12:05:00', PendingState::expiry($now, 300, null)->toDateTimeString());
        self::assertSame('2026-04-06 12:05:00', PendingState::expiry($now, 300, $now->addHour())->toDateTimeString());
        self::assertSame('2026-04-06 12:05:00', PendingState::expiry($now, 300, $now->addMinutes(5))->toDateTimeString());
        self::assertSame('2026-04-06 12:02:00', PendingState::expiry($now, 300, $now->addMinutes(2))->toDateTimeString());
    }

    /**
     * The requirements are stored as a JSON list of their values, in order.
     *
     * @return void
     */
    public function testTheRequirementsAreStoredAsAJsonListInOrder(): void
    {
        self::assertSame('["mfa","principal"]', PendingState::requires([PendingRequirement::MFA, PendingRequirement::PRINCIPAL]));
        self::assertSame('["principal"]', PendingState::requires([PendingRequirement::PRINCIPAL]));
    }

    /**
     * Filling sets the columns as stored without marking them persisted;
     * mirroring sets them as stored and as persisted, leaving every other
     * column as it was.
     *
     * @return void
     */
    public function testFillAndMirrorWriteTheColumnsAsStored(): void
    {
        $session = (new StubUncastSession)->forceFill(['guard' => 'api', 'requires' => null]);

        $session->syncOriginal();

        PendingState::fill($session, ['requires' => '["mfa"]']);

        self::assertSame('["mfa"]', $session->getAttributes()['requires']);
        self::assertTrue($session->isDirty('requires'));
        self::assertSame('api', $session->getAttributes()['guard']);

        PendingState::mirror($session, ['requires' => '["principal"]', 'tenant_id' => '7']);

        self::assertSame('["principal"]', $session->getRawOriginal('requires'));
        self::assertSame('7', $session->getRawOriginal('tenant_id'));
        self::assertFalse($session->isDirty(['requires', 'tenant_id']));
        self::assertSame('api', $session->getAttributes()['guard']);
    }

    /**
     * The state is a utility: it cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PendingState::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PendingState::class, $instance);
    }
}
