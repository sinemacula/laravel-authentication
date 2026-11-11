<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;

/**
 * Unit tests for the `SubjectType` enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectType::class)]
final class SubjectTypeTest extends TestCase
{
    /**
     * A subject is a person or a machine, carried in `sub_type` by those names.
     *
     * @return void
     */
    public function testASubjectIsAPersonOrAMachine(): void
    {
        self::assertSame([SubjectType::PERSON, SubjectType::MACHINE], SubjectType::cases());
        self::assertSame(['person', 'machine'], [SubjectType::PERSON->value, SubjectType::MACHINE->value]);
    }
}
