<?php

declare(strict_types = 1);

namespace Tests\Integration\Admission;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\ApplicationAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for asking the application policy on the write connection,
 * against two read/write splits whose replicas lag behind their primaries: the
 * identity's (the default connection) and the principal's (`landlord`).
 *
 * Each test writes a row through a split connection, so it exists on that
 * primary only, and the policy admits only when its query-builder read finds
 * it: an answer of `null` shows the read was served by the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationAdmission::class)]
final class ApplicationAdmissionTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Table of the rows the policy admits on. */
    private const string GRANTS = 'grants';

    /**
     * Create the grants table on both primaries and both replicas.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $definition = static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
        };

        $this->createOnPrimaryAndReplica(self::GRANTS, $definition);
        $this->createOnPrimaryAndReplica(self::GRANTS, $definition, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);
    }

    /**
     * Remove the temporary primary and replica files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * `admitIdentifier()` is asked with the identity's connection reading from
     * its writer, which reads from the replica again afterwards.
     *
     * @return void
     */
    public function testAdmitIdentifierIsAskedOnTheIdentitysWriter(): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table(self::GRANTS)->insert(['id' => 1]);

        $policy   = $this->policy();
        $identity = new StubPrincipal;

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $policy->admitIdentifier('api', $identity, 'email'));
        self::assertNull(ApplicationAdmission::admitIdentifier($policy, 'api', $identity, 'email'));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $policy->admitIdentifier('api', $identity, 'email'));
    }

    /**
     * `admit()` is asked with the identity's and the principal's connections
     * both reading from their writers, which read from their replicas again
     * afterwards.
     *
     * @return void
     */
    public function testAdmitIsAskedOnTheIdentitysAndThePrincipalsWriters(): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table(self::GRANTS)->insert(['id' => 1]);
        DB::connection(self::LANDLORD_CONNECTION)->table(self::GRANTS)->insert(['id' => 1]);

        $policy    = $this->policy();
        $identity  = new StubPrincipal;
        $principal = new class extends StubPrincipal {
            /** @var string|\UnitEnum|null The connection the principal is stored on. */
            protected $connection = 'landlord';
        };

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $policy->admit('api', $identity, $principal, null));
        self::assertNull(ApplicationAdmission::admit($policy, 'api', $identity, $principal, null));
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $policy->admit('api', $identity, $principal, null));
    }

    /**
     * The class is a static utility that cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ApplicationAdmission::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ApplicationAdmission::class, $instance);
    }

    /**
     * Use the lagging split as the default connection, beside a lagging
     * landlord split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
        $this->configureLaggingLandlordReplica(app(ConfigRepository::class));
    }

    /**
     * Create no package tables: the tests read only their own.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * A policy that admits the identity only when the identity's connection
     * finds a grant, and the principal only when both the identity's and the
     * principal's connections find one, each read through the query builder.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     */
    private function policy(): ApplicationPolicy
    {
        $granted = static fn (string $connection): bool => DB::connection($connection)->table(self::GRANTS)->exists();
        $policy  = self::createStub(ApplicationPolicy::class);

        $policy->method('admitIdentifier')->willReturnCallback(
            static fn (): ?FailureReason => $granted(self::SPLIT_CONNECTION) ? null : FailureReason::IDENTIFIER_UNVERIFIED,
        );

        $policy->method('admit')->willReturnCallback(
            static fn (): ?FailureReason => $granted(self::SPLIT_CONNECTION) && $granted(self::LANDLORD_CONNECTION) ? null : FailureReason::PRINCIPAL_INELIGIBLE,
        );

        return $policy;
    }
}
