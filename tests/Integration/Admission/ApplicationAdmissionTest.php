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
 * Integration tests for asking the application policy on the write connection
 * of a lagging read/write split.
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
     * Create the grants table on the primary and the replica.
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
     * Use the lagging split as the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
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
     * finds a grant, read through the query builder.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     */
    private function policy(): ApplicationPolicy
    {
        $policy = self::createStub(ApplicationPolicy::class);

        $policy->method('admitIdentifier')->willReturnCallback(
            static fn (): ?FailureReason => DB::connection(self::SPLIT_CONNECTION)->table(self::GRANTS)->exists() ? null : FailureReason::IDENTIFIER_UNVERIFIED,
        );

        return $policy;
    }
}
