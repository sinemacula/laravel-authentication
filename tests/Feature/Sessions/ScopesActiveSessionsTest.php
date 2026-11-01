<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ScopesActiveSessions;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use Tests\Integration\Fixtures\ScopedRenamedPruningSession;
use Tests\TestCase;

/**
 * Feature tests for the rule that decides which sessions are active, as the
 * `active()` scope and the session list apply it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveSessions::class)]
#[CoversTrait(ScopesActiveSessions::class)]
final class ScopesActiveSessionsTest extends TestCase
{
    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The scope keeps sessions that are active, unrevoked and strictly before
     * both deadlines, an absolute deadline of `null` being none, with qualified
     * columns, and the current second.
     *
     * @return void
     */
    public function testTheScopeKeepsActiveUnrevokedSessionsBeforeBothDeadlines(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2027-01-15 10:00:00'));

        $query = Session::query()->active();

        self::assertSame(
            'select * from authentication_sessions where authentication_sessions.status = ?'
            . ' and authentication_sessions.revoked_at is null'
            . ' and authentication_sessions.idle_expires_at > ?'
            . ' and (authentication_sessions.absolute_expires_at is null or authentication_sessions.absolute_expires_at > ?)',
            str_replace(['"', '`'], '', $query->toSql()),
        );
        self::assertSame(['active', '2027-01-15 10:00:00', '2027-01-15 10:00:00'], $query->getBindings());
    }

    /**
     * The columns come from the model's name accessors.
     *
     * @return void
     */
    public function testTheColumnsComeFromTheNameAccessors(): void
    {
        $session = new ScopedRenamedPruningSession;
        $query   = $session->newQueryWithoutScopes();

        ActiveSessions::constrain($query, $session, CarbonImmutable::parse('2027-01-15 10:00:00'));

        self::assertSame(
            'select * from scoped_renamed_pruning_sessions where scoped_renamed_pruning_sessions.status = ?'
                . ' and scoped_renamed_pruning_sessions.ended_at is null'
                . ' and scoped_renamed_pruning_sessions.idle_until > ?'
                . ' and (scoped_renamed_pruning_sessions.valid_until is null or scoped_renamed_pruning_sessions.valid_until > ?)',
            str_replace(['"', '`'], '', $query->toSql()),
        );
    }

    /**
     * `ActiveSessions` is a static utility; instantiation is disallowed through
     * the private constructor. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ActiveSessions::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
