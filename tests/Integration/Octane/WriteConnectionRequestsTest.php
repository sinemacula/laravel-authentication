<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\TestCase;

/**
 * End-to-end tests for `WriteConnection::during()` served by one Laravel Octane
 * worker. Eloquent's connection resolver is process-wide, so it outlives the
 * request's sandbox, and so does the database connection whose read mode a pin
 * changes. Against a split connection whose replica lags, a session written
 * through it is on the primary only: a pinned read finds it, and an ordinary
 * read misses it. Whether the pin's callback returns or throws, the next
 * request reads through the database manager again, from the replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
#[CoversClass(PinningConnectionResolver::class)]
final class WriteConnectionRequestsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessionRecords, ServesRequestsThroughOctane;

    /** @var list<bool> Whether each pinned read found the session. */
    private array $pinnedReads = [];

    /**
     * Add the routes and boot the worker.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/sessions/{id}', static fn (string $id): array => [
            'found'    => Session::query()->find($id) instanceof Session,
            'resolver' => Model::getConnectionResolver() === app('db'),
        ]);

        Route::post('/pinned/{id}', fn (string $id): array => ['found' => $this->readPinned($id, false)]);
        Route::post('/pinned/{id}/throw', fn (string $id): array => ['found' => $this->readPinned($id, true)]);

        Route::post('/nested/{id}/throw', function (string $id): array {
            try {
                WriteConnection::during(new Session, fn (): bool => $this->readPinned($id, true));
            } catch (\RuntimeException) {
                return ['found' => Session::query()->find($id) instanceof Session];
            }

            return ['found' => null];
        });

        $this->bootOctaneWorker();
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
     * A pinned read in one request finds the session on the primary; the next
     * request reads through the database manager, from the replica, and misses
     * it.
     *
     * @return void
     */
    public function testAPinThatReturnsIsReleasedForTheNextRequest(): void
    {
        $session = $this->seedSession();

        $this->serve(self::octaneRequest('POST', "/pinned/{$session}"))->assertExactJson(['found' => true]);
        $this->serve(self::octaneRequest('GET', "/sessions/{$session}"))->assertExactJson(['found' => false, 'resolver' => true]);
    }

    /**
     * A pin whose callback throws, out of the request and into the exception
     * handler, is released all the same: the read inside it found the session,
     * and the next request reads from the replica through the database manager.
     *
     * @return void
     */
    public function testAPinThatThrowsIsReleasedForTheNextRequest(): void
    {
        $session = $this->seedSession();

        $this->serve(self::octaneRequest('POST', "/pinned/{$session}/throw"))->assertServerError();

        self::assertSame([true], $this->pinnedReads);

        $this->serve(self::octaneRequest('GET', "/sessions/{$session}"))->assertExactJson(['found' => false, 'resolver' => true]);

        self::assertSame($this->app?->make('db'), Model::getConnectionResolver());
    }

    /**
     * A pin that throws inside another releases both: the rest of the request
     * that caught it, and the next request, read from the replica.
     *
     * @return void
     */
    public function testANestedPinThatThrowsReleasesBoth(): void
    {
        $session = $this->seedSession();

        $this->serve(self::octaneRequest('POST', "/nested/{$session}/throw"))->assertExactJson(['found' => false]);

        self::assertSame([true], $this->pinnedReads);

        $this->serve(self::octaneRequest('GET', "/sessions/{$session}"))->assertExactJson(['found' => false, 'resolver' => true]);
    }

    /**
     * Use the lagging split connection.
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
     * Create the package tables on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Read the session inside a pin, recording whether it was found, and throw
     * from the pin's callback when asked to.
     *
     * @param  string  $id
     * @param  bool  $throw
     * @return bool
     *
     * @throws \RuntimeException
     */
    private function readPinned(string $id, bool $throw): bool
    {
        return WriteConnection::during(new Session, function () use ($id, $throw): bool {
            $found = Session::query()->find($id) instanceof Session;

            $this->pinnedReads[] = $found;

            if ($throw) {
                throw new \RuntimeException('The pinned lookup failed.');
            }

            return $found;
        });
    }

    /**
     * Write a session through the split connection, so it exists on the primary
     * only, and return its key.
     *
     * @return string
     */
    private function seedSession(): string
    {
        $session = new Session;
        $session->forceFill([...self::liveSession(), 'authenticatable_type' => 'identity', 'authenticatable_id' => '1'])->save();

        $key = $session->getKey();

        self::assertIsString($key);

        return $key;
    }
}
