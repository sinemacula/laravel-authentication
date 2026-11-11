<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\UuidKeyedPrincipal;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for the session's `principal()` relation with integer and
 * UUID keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Session::class)]
final class SessionPrincipalIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /**
     * Create an integer-keyed and a UUID-keyed principal table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('uuid_keyed_principals', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the principal tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('uuid_keyed_principals');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * A session loaded on its own resolves its integer-keyed or UUID-keyed
     * principal, and a session that records none has none.
     *
     * @return void
     */
    public function testResolvesAPrincipalOfAnyKeyType(): void
    {
        [$integerKeyed, $uuidKeyed] = $this->principals();

        $first  = $this->sessionActingAs($integerKeyed);
        $second = $this->sessionActingAs($uuidKeyed);
        $none   = $this->sessionActingAs(null);

        $this->assertResolves($integerKeyed, $this->reload($first)->principal);
        $this->assertResolves($uuidKeyed, $this->reload($second)->principal);

        self::assertNull($this->reload($none)->principal);
    }

    /**
     * Eager loading the principals of sessions acting as principals of both key
     * types resolves each one.
     *
     * @return void
     */
    public function testEagerLoadsPrincipalsOfEveryKeyType(): void
    {
        [$integerKeyed, $uuidKeyed] = $this->principals();

        $first  = $this->sessionActingAs($integerKeyed);
        $second = $this->sessionActingAs($uuidKeyed);

        $sessions = Session::query()->with('principal')->get()->keyBy(static fn (Session $session): string => $session->id);

        self::assertCount(2, $sessions);

        foreach ([[$first, $integerKeyed], [$second, $uuidKeyed]] as [$session, $principal]) {

            $loaded = $sessions->get($session->id);

            self::assertInstanceOf(Session::class, $loaded);
            self::assertTrue($loaded->relationLoaded('principal'));

            $this->assertResolves($principal, $loaded->principal);
        }
    }

    /**
     * Persist one integer-keyed and one UUID-keyed principal.
     *
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \Tests\Integration\Fixtures\UuidKeyedPrincipal}
     */
    private function principals(): array
    {
        $integerKeyed            = new StubPrincipal;
        $integerKeyed->email     = 'integer-keyed@example.test';
        $integerKeyed->password  = 'irrelevant';
        $integerKeyed->is_active = true;
        $integerKeyed->save();

        $uuidKeyed = new UuidKeyedPrincipal;
        $uuidKeyed->save();

        return [$integerKeyed, $uuidKeyed];
    }

    /**
     * Persist a live session of the integer-keyed identity acting as the given
     * principal, or as none.
     *
     * @param  ?\Illuminate\Database\Eloquent\Model  $principal
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function sessionActingAs(?Model $principal): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => '1',
            'principal_type'       => $principal?->getMorphClass(),
            'principal_id'         => $principal === null ? null : (string) $principal->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return $session;
    }

    /**
     * Load a session again from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function reload(Session $session): Session
    {
        return Session::query()->whereKey($session->getKey())->firstOrFail();
    }

    /**
     * Assert that a resolved principal is the expected row.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $expected
     * @param  mixed  $resolved
     * @return void
     */
    private function assertResolves(Model $expected, mixed $resolved): void
    {
        self::assertInstanceOf($expected::class, $resolved);
        self::assertTrue($expected->is($resolved));
    }
}
