<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubNonModelSession;
use Tests\Unit\Stubs\StubSession;

/**
 * Unit tests for the InvalidSessionModelConfigurationException.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidSessionModelConfigurationException::class)]
final class InvalidSessionModelConfigurationExceptionTest extends TestCase
{
    /**
     * `validate()` passes silently for a valid EloquentSession model.
     *
     * @return void
     */
    public function testValidatePassesForValidEloquentSessionModel(): void
    {
        InvalidSessionModelConfigurationException::validate(StubSession::class);

        self::assertTrue(true, 'validate() did not throw for a valid session model.');
    }

    /**
     * `validate()` throws for an empty class string.
     *
     * @return void
     */
    public function testValidateThrowsForEmptyString(): void
    {
        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage('(empty string)');

        InvalidSessionModelConfigurationException::validate('');
    }

    /**
     * `validate()` throws for a nonexistent class.
     *
     * @return void
     */
    public function testValidateThrowsForNonexistentClass(): void
    {
        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage('App\Models\FakeSession');

        InvalidSessionModelConfigurationException::validate('App\Models\FakeSession');
    }

    /**
     * `validate()` throws for a class that is not an Eloquent model.
     *
     * @return void
     */
    public function testValidateThrowsForNonModelClass(): void
    {
        $this->expectException(InvalidSessionModelConfigurationException::class);

        InvalidSessionModelConfigurationException::validate(\stdClass::class);
    }

    /**
     * `validate()` throws for a class that declares the Eloquent session
     * contract but is not an Eloquent model.
     *
     * @return void
     */
    public function testValidateThrowsForEloquentSessionThatIsNotAModel(): void
    {
        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage(StubNonModelSession::class);

        InvalidSessionModelConfigurationException::validate(StubNonModelSession::class);
    }

    /**
     * `validate()` throws for a Model that does not implement EloquentSession.
     *
     * @return void
     */
    public function testValidateThrowsForModelWithoutEloquentSession(): void
    {
        $this->expectException(InvalidSessionModelConfigurationException::class);

        InvalidSessionModelConfigurationException::validate(StubBareSession::class);
    }

    /**
     * `unsupported()` builds an exception with the configured class in the
     * message.
     *
     * @return void
     */
    public function testUnsupportedIncludesConfiguredClassInMessage(): void
    {
        $exception = InvalidSessionModelConfigurationException::unsupported('App\BadSession');

        self::assertStringContainsString('App\BadSession', $exception->getMessage());
        self::assertStringContainsString(
            EloquentSession::class,
            $exception->getMessage(),
        );
    }

    /**
     * `unsupported()` substitutes `(empty string)` when the configured class is
     * empty.
     *
     * @return void
     */
    public function testUnsupportedDisplaysEmptyStringPlaceholder(): void
    {
        $exception = InvalidSessionModelConfigurationException::unsupported('');

        self::assertStringContainsString('(empty string)', $exception->getMessage());
    }

    /**
     * `offStorage()` names the configured class, both settings and both
     * connections.
     *
     * @return void
     */
    public function testOffStorageNamesTheClassAndBothConnections(): void
    {
        $exception = InvalidSessionModelConfigurationException::offStorage('App\StoreSession', 'sessions_db', 'auth_db');

        self::assertSame(
            'authentication.session.model [App\StoreSession] must live on the storage connection (authentication.storage.connection),'
                . ' where the package writes its sessions with its other rows in one transaction: the session model is on [sessions_db],'
                . ' the storage connection is [auth_db].',
            $exception->getMessage(),
        );
    }
}
