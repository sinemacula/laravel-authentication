<?php

declare(strict_types = 1);

namespace Tests\Integration\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\NamedIdentity;
use Tests\TestCase;

/**
 * Integration tests for API keys whose principal columns are under a collation
 * that counts distinct identifiers as equal: a principal whose type or
 * identifier differs from the key's only in case or accent finds, lists,
 * rotates and revokes none of its keys, while the exact principal still manages
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyService::class)]
final class CollationEqualPrincipalApiKeysTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithMachineCredentials;

    /** @var string The identifier of the principal the key is issued for. */
    private const string OWNER = 'alice';

    /**
     * Create the tables with the principal columns folded, and freeze the
     * clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::foldColumns('api_keys', ['principal_type', 'principal_id']);
        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * A principal whose identifier differs from the key's only in case or
     * accent finds, lists, revokes and rotates none of its keys, which are left
     * as they were with nothing reported, while the exact principal still finds
     * and lists the key, and rotates it.
     *
     * @param  string  $folded
     * @return void
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherIdentifierTheCollationCountsAsEqualHasNoKeys(string $folded): void
    {
        $id = $this->issueKeyRecording(NamedIdentity::class, self::OWNER);

        self::assertColumnFolds('api_keys', 'principal_id', $folded);

        $this->assertAbsentTo(self::namedIdentity($folded), $id);

        $owner = self::namedIdentity(self::OWNER);

        self::assertSame($id, $this->apiKeys()->find($owner, $id)?->id);
        self::assertSame([$id], array_map(static fn (ApiKeySummary $summary): string => $summary->id, $this->apiKeys()->keys($owner)));
        self::assertNotNull($this->apiKeys()->rotate($owner, $id));
    }

    /**
     * A principal whose type differs from the key's only in case finds, lists,
     * revokes and rotates none of its keys, which are left as they were with
     * nothing reported.
     *
     * @return void
     */
    public function testAnotherTypeTheCollationCountsAsEqualHasNoKeys(): void
    {
        $id = $this->issueKeyRecording(strtolower(NamedIdentity::class), self::OWNER);

        self::assertColumnFolds('api_keys', 'principal_type', NamedIdentity::class);

        $this->assertAbsentTo(self::namedIdentity(self::OWNER), $id);
    }

    /**
     * The exact principal revokes its key once the collation-equal one could
     * not.
     *
     * @param  string  $folded
     * @return void
     */
    #[DataProvider('provideFoldedKeys')]
    public function testTheExactPrincipalStillRevokesItsKey(string $folded): void
    {
        $id = $this->issueKeyRecording(NamedIdentity::class, self::OWNER);

        self::assertColumnFolds('api_keys', 'principal_id', $folded);
        self::assertFalse($this->apiKeys()->revoke(self::namedIdentity($folded), $id));
        self::assertTrue($this->apiKeys()->revoke(self::namedIdentity(self::OWNER), $id));
        self::assertNotNull(DB::table('api_keys')->where('id', $id)->value('revoked_at'));
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }

    /**
     * Issue a key to a machine and record it as held for the principal with the
     * type and identifier, as an application whose principals are keyed by name
     * would hold it, and return its id.
     *
     * @param  string  $type
     * @param  string  $id
     * @return string
     */
    private function issueKeyRecording(string $type, string $id): string
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        DB::table('api_keys')->where('id', $issued->id)->update(['principal_type' => $type, 'principal_id' => $id]);

        return $issued->id;
    }

    /**
     * Assert the principal finds, lists, revokes and rotates none of the keys,
     * that the key is left as it was, and that nothing is reported.
     *
     * @param  \Tests\Integration\Fixtures\NamedIdentity  $principal
     * @param  string  $id
     * @return void
     */
    private function assertAbsentTo(NamedIdentity $principal, string $id): void
    {
        $this->recordMachineEvents([ApiKeyRevoked::class, ApiKeyRotated::class]);

        self::assertNull($this->apiKeys()->find($principal, $id));
        self::assertSame([], $this->apiKeys()->keys($principal));
        self::assertFalse($this->apiKeys()->revoke($principal, $id));
        self::assertNull($this->apiKeys()->rotate($principal, $id));

        $row = DB::table('api_keys')->where('id', $id)->first();

        self::assertNotNull($row);
        self::assertNull($row->revoked_at);
        self::assertNull($row->rotated_at);
        self::assertNull($row->expires_at);
        self::assertSame(1, DB::table('api_keys')->count());
        self::assertSame([], $this->machineEvents);
    }
}
