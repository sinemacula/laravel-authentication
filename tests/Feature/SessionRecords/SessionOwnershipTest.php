<?php

declare(strict_types = 1);

namespace Tests\Feature\SessionRecords;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for `SessionOwnership`, which reads a session row's owner and
 * decides whether an identity is that owner.
 *
 * Runs on the Testbench application because building the `authenticatable`
 * relation needs a database connection, although no query is made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionOwnership::class)]
final class SessionOwnershipTest extends TestCase
{
    use InteractsWithSessionRecords;

    /**
     * The owner key is the session row's owner key column as a string, or
     * `null` when the row records none.
     *
     * @return void
     */
    public function testOwnerKeyReadsTheOwnerKeyColumn(): void
    {
        self::assertSame('9', SessionOwnership::ownerKey($this->record(StubIdentity::class, '9')));
        self::assertSame('9', SessionOwnership::ownerKey($this->record(StubIdentity::class, 9)));
        self::assertNull(SessionOwnership::ownerKey($this->record(StubIdentity::class, null)));
    }

    /**
     * Rows of `[identity, expected]` against a `StubIdentity` session owned by
     * key `9`.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity, 1: bool}>
     */
    public static function provideIdentities(): iterable
    {
        yield from [
            'the owner'                        => [static fn (): Identity => (new StubIdentity)->forceFill(['id' => 9]), true],
            'the owner with a string key'      => [static fn (): Identity => (new StubIdentity)->forceFill(['id' => '9']), true],
            'the owner model with another key' => [static fn (): Identity => (new StubIdentity)->forceFill(['id' => 10]), false],
            'another model with the owner key' => [static fn (): Identity => (new StubPrincipal)->forceFill(['id' => 9]), false],
            'an identity that is not a model'  => [static fn (): Identity => \Mockery::mock(Identity::class), false],
        ];
    }

    /**
     * Only an Eloquent identity of the session row's morph type with the
     * session row's owner key is the owner.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideIdentities')]
    public function testIsOwnerAcceptsOnlyTheExactOwner(\Closure $identity, bool $expected): void
    {
        self::assertSame($expected, SessionOwnership::isOwner($this->record(StubIdentity::class, '9'), $identity()));
    }

    /**
     * A session row with no owner key has no owner, so no identity matches it,
     * not even one whose key is also empty.
     *
     * @return void
     */
    public function testIsOwnerRejectsEveryIdentityForASessionWithoutAnOwnerKey(): void
    {
        self::assertFalse(SessionOwnership::isOwner($this->record(StubIdentity::class, null), new StubIdentity));
    }

    /**
     * The row stored under a session's key is that session only while it
     * records the same generation and the same owner's type and key: another
     * generation, another owner of the same type or the same key of another
     * type, and a session that is not an Eloquent one are not.
     *
     * @return void
     */
    public function testTheStoredRowIsTheSessionOnlyWithItsGenerationAndOwner(): void
    {
        $given = $this->record(StubIdentity::class, '9')->forceFill(['generation' => 'gen-1']);

        self::assertTrue(SessionOwnership::isSameSession($given, (clone $given)->forceFill(['authenticatable_id' => 9])));
        self::assertFalse(SessionOwnership::isSameSession($given, (clone $given)->forceFill(['generation' => 'gen-2'])));
        self::assertFalse(SessionOwnership::isSameSession($given, (clone $given)->forceFill(['authenticatable_id' => '10'])));
        self::assertFalse(SessionOwnership::isSameSession($given, (clone $given)->forceFill(['authenticatable_type' => StubPrincipal::class])));
        self::assertFalse(SessionOwnership::isSameSession(\Mockery::mock(Session::class), $given));
    }

    /**
     * `SessionOwnership` is a static utility; instantiation is disallowed via
     * the private constructor so consumers cannot create a stateful
     * session-ownership helper. Reflection invokes the private constructor so
     * the line is covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionOwnership::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SessionOwnership::class, $instance);
    }

    /**
     * A session whose recorded owner type is mapped through the morph map, or
     * is not a class at all, is judged by the class the type names.
     *
     * @return void
     */
    public function testAMachineOwnedSessionIsJudgedByTheClassItsTypeNames(): void
    {
        $session = new StubSession;

        self::assertFalse(SessionOwnership::isMachineOwned($session));

        $session->forceFill(['authenticatable_type' => MachineClient::class]);

        self::assertTrue(SessionOwnership::isMachineOwned($session));

        $session->forceFill(['authenticatable_type' => 'not-a-class']);

        self::assertFalse(SessionOwnership::isMachineOwned($session));

        $session->forceFill(['authenticatable_type' => IntegrationIdentity::class]);

        self::assertFalse(SessionOwnership::isMachineOwned($session));

        Relation::morphMap(['robot' => MachineClient::class]);

        try {
            $session->forceFill(['authenticatable_type' => 'robot']);

            self::assertTrue(SessionOwnership::isMachineOwned($session));
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * Build an unsaved session row recording the supplied owner.
     *
     * @param  string  $type
     * @param  int|string|null  $key
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function record(string $type, int|string|null $key): StubSession
    {
        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $type,
            'authenticatable_id'   => $key,
        ]);

        return $session;
    }
}
