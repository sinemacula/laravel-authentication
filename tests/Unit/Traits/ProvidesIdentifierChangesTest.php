<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierChanges;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use Tests\Unit\Stubs\StubChangeableModel;
use Tests\Unit\Stubs\StubVerifiableModel;

/**
 * Unit tests for the ProvidesIdentifierChanges trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesIdentifierChanges::class)]
final class ProvidesIdentifierChangesTest extends TestCase
{
    /**
     * The trait brings the verification with it, so a changeable model uses it
     * alone, and a model that only verifies its identifiers gets no public
     * `replaceIdentifier()` its contracts do not ask for.
     *
     * @return void
     */
    public function testOnlyTheChangesTraitCarriesTheReplacement(): void
    {
        self::assertContains(ProvidesIdentifierVerification::class, class_uses(ProvidesIdentifierChanges::class));
        self::assertFalse(method_exists(StubVerifiableModel::class, 'replaceIdentifier'));
    }

    /**
     * A type that is not a valid identifier type is refused before the
     * identity's connection is reached.
     *
     * @return void
     */
    public function testAMalformedTypeIsRefusedBeforeAnyQuery(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier type [users.email] must be');

        (new StubChangeableModel)->replaceIdentifier('users.email', null, 'new@example.test');
    }
}
