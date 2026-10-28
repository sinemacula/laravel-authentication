<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use SineMacula\Laravel\Authentication\Events\ContextEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Unit tests for the API key lifecycle events: each keeps its context, the
 * rotation the replaced key's id, and each survives a queue.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyIssued::class)]
#[CoversClass(ApiKeyRevoked::class)]
#[CoversClass(ApiKeyRotated::class)]
#[CoversClass(ContextEvent::class)]
final class ApiKeyEventsTest extends TestCase
{
    /**
     * Each event keeps its context, and the rotation the replaced key's id.
     *
     * @return void
     */
    public function testKeepTheirContext(): void
    {
        $context = self::context();
        $rotated = new ApiKeyRotated($context, 'key-0');

        foreach ([new ApiKeyIssued($context), new ApiKeyRevoked($context), $rotated] as $event) {
            self::assertInstanceOf(AuthenticationEvent::class, $event);
            self::assertSame($context, $event->context());
            self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
            self::assertContains(SerializesModels::class, class_uses_recursive($event));
        }

        self::assertSame($context, $rotated->context);
        self::assertSame('key-0', $rotated->previousKeyId);
    }

    /**
     * The rotation survives a round trip with the key ids and scopes.
     *
     * @return void
     */
    public function testARotationSurvivesAQueue(): void
    {
        $copy = unserialize(serialize(new ApiKeyRotated(self::context(), 'key-0')));

        self::assertInstanceOf(ApiKeyRotated::class, $copy);
        self::assertSame('key-0', $copy->previousKeyId);
        self::assertSame('key-1', $copy->context->credentialId);
        self::assertSame(['read'], $copy->context->scopes);
    }

    /**
     * A context naming the new key.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        $client = new ClientContext('203.0.113.7', 'agent');

        return new EventContext('machine', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), credentialId: 'key-1', scopes: ['read']);
    }
}
