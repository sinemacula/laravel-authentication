<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;
use SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubVerifiableIdentity;

/**
 * Unit tests for the identifier change notifier fake tests bind in place of the
 * application's notifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeIdentifierChangeNotifier::class)]
final class FakeIdentifierChangeNotifierTest extends TestCase
{
    /**
     * Restore the global container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * `fake()` binds a fresh instance as the notifier in the container given,
     * or in the global container when none is, and returns it.
     *
     * @return void
     */
    public function testFakeBindsAFreshInstanceAsTheNotifier(): void
    {
        $given = new Container;
        $fake  = FakeIdentifierChangeNotifier::fake($given);

        self::assertSame($fake, $given->make(IdentifierChangeNotifier::class));

        $global = new Container;

        Container::setInstance($global);

        $other = FakeIdentifierChangeNotifier::fake();

        self::assertNotSame($fake, $other);
        self::assertSame($other, $global->make(IdentifierChangeNotifier::class));
    }

    /**
     * Notices are kept in order, filtered on request, counted and forgotten.
     *
     * @return void
     */
    public function testKeepsCountsFiltersAndForgetsNotices(): void
    {
        $fake  = new FakeIdentifierChangeNotifier;
        $email = self::notice(new PlainIdentityFixture(1), 'email');
        $phone = self::notice(new PlainIdentityFixture(1), 'phone');

        self::assertSame([[], false, 0], [$fake->sent(), $fake->hasSent(), $fake->count()]);

        $fake->notify($email);
        $fake->notify($phone);

        $isPhone = static fn (IdentifierChangeNotice $notice): bool => $notice->type === 'phone';

        self::assertSame([$email, $phone], $fake->sent());
        self::assertSame([$phone], $fake->sent($isPhone));
        self::assertTrue($fake->hasSent($isPhone));
        self::assertFalse($fake->hasSent(static fn (IdentifierChangeNotice $notice): bool => $notice->type === 'username'));
        self::assertSame(2, $fake->count());

        $fake->forget();

        self::assertSame([[], 0], [$fake->sent(), $fake->count()]);
    }

    /**
     * The notices for an identity are those about that very identity: an
     * Eloquent one by its class, table and key, any other by its class and auth
     * identifier.
     *
     * @return void
     */
    public function testFindsTheNoticesForAnIdentity(): void
    {
        $fake   = new FakeIdentifierChangeNotifier;
        $model  = self::changeable(1);
        $plain  = new PlainIdentityFixture(1);
        $notice = [
            self::notice($model, 'email'),
            self::notice(self::changeable(2), 'email'),
            self::notice($plain, 'email'),
            self::notice(new StubVerifiableIdentity(1, []), 'email'),
        ];

        foreach ($notice as $sent) {
            $fake->notify($sent);
        }

        self::assertSame([$notice[0]], $fake->noticesFor(self::changeable(1)));
        self::assertSame([$notice[2]], $fake->noticesFor(new PlainIdentityFixture('1')));
        self::assertSame([$notice[3]], $fake->noticesFor(new StubVerifiableIdentity(1, [])));
        self::assertSame([], $fake->noticesFor(new PlainIdentityFixture(3)));
    }

    /**
     * A notice of a change of the identity's identifier of the type.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice
     */
    private static function notice(Identity $identity, string $type): IdentifierChangeNotice
    {
        return new IdentifierChangeNotice('web', $type, 'old', 'new', $identity, CarbonImmutable::parse('2027-03-01 08:30:00'));
    }

    /**
     * An unsaved changeable identity with the key.
     *
     * @param  int  $id
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     */
    private static function changeable(int $id): ChangeableIdentity
    {
        return (new ChangeableIdentity)->forceFill(['id' => $id]);
    }
}
