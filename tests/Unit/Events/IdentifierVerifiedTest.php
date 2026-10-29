<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * IdentifierVerified event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierVerified::class)]
final class IdentifierVerifiedTest extends TestCase
{
    /**
     * The event carries the guard, the identity, the identifier's type and the
     * client, never the identifier itself; the client is optional.
     *
     * @return void
     */
    public function testCarriesTheContextButNotTheIdentifier(): void
    {
        $identity = new PlainIdentityFixture(7);
        $client   = new ClientContext('203.0.113.7', 'Mail/1.0');
        $event    = new IdentifierVerified('api', $identity, 'email', $client);

        self::assertSame('api', $event->guard);
        self::assertSame($identity, $event->identity);
        self::assertSame('email', $event->type);
        self::assertSame($client, $event->client);
        self::assertSame(['guard', 'identity', 'type', 'client'], array_keys(get_object_vars($event)));
        self::assertNull((new IdentifierVerified('api', $identity, 'phone'))->client);
    }

    /**
     * The event serialises its models for queued listeners and leaves waiting
     * for the commit to the verifier, which waits for the identity's own
     * connection only.
     *
     * @return void
     */
    public function testSerialisesModelsAndLeavesTheCommitToTheVerifier(): void
    {
        $event = new IdentifierVerified('api', new PlainIdentityFixture(7), 'email', new ClientContext('203.0.113.7', null));

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses($event));

        $roundTripped = unserialize(serialize($event));

        self::assertInstanceOf(IdentifierVerified::class, $roundTripped);
        self::assertSame(7, $roundTripped->identity->getAuthIdentifier());
        self::assertSame('203.0.113.7', $roundTripped->client?->ip);
    }
}
