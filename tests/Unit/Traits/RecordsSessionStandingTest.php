<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\RecordsSessionStanding;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use Tests\Unit\Stubs\StubSession;
use Tests\Unit\Stubs\StubUncastSession;

/**
 * Unit tests for the accessors behind a session's standing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(RecordsSessionStanding::class)]
final class RecordsSessionStandingTest extends TestCase
{
    /**
     * Unset the facade application so the shipped model resolves no
     * configuration an earlier test left behind.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
    }

    /**
     * The standing is read as stored, on a model without casts.
     *
     * @return void
     */
    public function testReadsTheRecordedStanding(): void
    {
        $session = (new StubUncastSession)->forceFill([
            'status'                => 'pending',
            'requires'              => '["mfa","principal"]',
            'pending_key'           => 'digest',
            'tenant_id'             => '42',
            'tenant_policy_version' => 'v3',
        ]);

        self::assertSame(SessionStatus::PENDING, $session->getStatus());
        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $session->getRequires());
        self::assertSame('digest', $session->getPendingKey());
        self::assertSame('42', $session->getTenantId());
        self::assertSame('v3', $session->getTenantPolicyVersion());
    }

    /**
     * An active session waits on nothing and holds no pending digest, active
     * tenant or version.
     *
     * @return void
     */
    public function testReadsAnActiveSessionAndTheShippedModelsCasts(): void
    {
        $active = (new StubUncastSession)->forceFill(['status' => 'active', 'requires' => null, 'pending_key' => null, 'tenant_id' => null, 'tenant_policy_version' => null]);

        self::assertSame(SessionStatus::ACTIVE, $active->getStatus());
        self::assertSame([], $active->getRequires());
        self::assertNull($active->getPendingKey());
        self::assertNull($active->getTenantId());
        self::assertNull($active->getTenantPolicyVersion());

        $cast = (new Session)->forceFill(['requires' => ['principal']]);

        self::assertSame(SessionStatus::ACTIVE, $cast->getStatus());
        self::assertSame([PendingRequirement::PRINCIPAL], $cast->getRequires());
        self::assertSame('["principal"]', $cast->getAttributes()['requires']);
    }

    /**
     * Rows of `[stored status]` the package does not know.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnknownStatuses(): iterable
    {
        yield 'null' => [null];
        yield 'another word' => ['suspended'];
        yield 'another case' => ['ACTIVE'];
        yield 'a number' => [1];
    }

    /**
     * A status the package does not know fails closed: the session is never
     * taken for an active one it may not be.
     *
     * @param  mixed  $status
     * @return void
     */
    #[DataProvider('provideUnknownStatuses')]
    public function testAnUnknownStatusThrows(mixed $status): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('is not one the package knows');

        (new StubUncastSession)->forceFill(['status' => $status])->getStatus();
    }

    /**
     * Rows of `[stored requirements]` that are not a list the package knows.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnknownRequirements(): iterable
    {
        yield 'an unknown requirement' => ['["mfa","tenant"]'];
        yield 'not a list' => ['{"first":"mfa"}'];
        yield 'not text' => ['[1]'];
        yield 'a scalar' => ['"mfa"'];
        yield 'not JSON' => ['mfa'];
    }

    /**
     * Requirements the package does not know fail closed.
     *
     * @param  mixed  $requires
     * @return void
     */
    #[DataProvider('provideUnknownRequirements')]
    public function testUnknownRequirementsThrow(mixed $requires): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('are not a list the package knows');

        (new StubUncastSession)->forceFill(['requires' => $requires])->getRequires();
    }

    /**
     * Rows of `[read, name accessor]`: each part of the standing that must be
     * loaded.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Unit\Stubs\StubSession): mixed, 1: string}>
     */
    public static function provideStateAccessors(): iterable
    {
        yield 'status' => [static fn (StubSession $session): mixed => $session->getStatus(), 'getStatusName'];
        yield 'requirements' => [static fn (StubSession $session): mixed => $session->getRequires(), 'getRequiresName'];
        yield 'pending digest' => [static fn (StubSession $session): mixed => $session->getPendingKey(), 'getPendingKeyName'];
        yield 'active tenant' => [static fn (StubSession $session): mixed => $session->getTenantId(), 'getTenantIdName'];
        yield 'policy version' => [static fn (StubSession $session): mixed => $session->getTenantPolicyVersion(), 'getTenantPolicyVersionName'];
    }

    /**
     * A session loaded without a part of its standing reports the
     * misconfiguration rather than reading it as absent.
     *
     * @param  \Closure(\Tests\Unit\Stubs\StubSession): mixed  $read
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideStateAccessors')]
    public function testAnUnloadedPartThrows(\Closure $read, string $name): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($name . '()');

        $read(new StubSession);
    }

    /**
     * The columns have their conventional names.
     *
     * @return void
     */
    public function testColumnNames(): void
    {
        $session = new StubSession;

        self::assertSame('status', $session->getStatusName());
        self::assertSame('requires', $session->getRequiresName());
        self::assertSame('pending_key', $session->getPendingKeyName());
        self::assertSame('supersedes_session_id', $session->getSupersedesSessionIdName());
        self::assertSame('supersedes_refresh_key', $session->getSupersedesRefreshKeyName());
        self::assertSame('attempt_windows', $session->getAttemptWindowsName());
        self::assertSame('tenant_id', $session->getTenantIdName());
        self::assertSame('tenant_policy_version', $session->getTenantPolicyVersionName());
    }
}
