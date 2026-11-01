<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Unit tests for the shipped session model built before the Config facade is
 * bootstrapped, as a data provider builds one: it takes the default table and
 * the default connection rather than failing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Session::class)]
final class SessionWithoutApplicationTest extends TestCase
{
    /**
     * Unset the facade application, so no facade has a root.
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
     * The model takes the `authentication_sessions` table on the default
     * connection.
     *
     * @return void
     */
    public function testTakesTheDefaultTableAndConnection(): void
    {
        $session = new Session;

        self::assertSame('authentication_sessions', $session->getTable());
        self::assertNull($session->getConnectionName());
    }
}
