<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use Tests\Fixtures\Sessions\PlainCutoffIdentity;
use Tests\Fixtures\Sessions\PlainCutoffPrincipal;
use Tests\Integration\Fixtures\RecheckedMember;
use Tests\Integration\Fixtures\RecheckedMembership;
use Tests\TestCase;

/**
 * Feature tests for the sessions a bulk revocation kept on purpose: the floor a
 * holder's cutoff must pass to end a session's call is the call's start, or the
 * latest cutoff a revocation that kept that session moved for that holder, with
 * sessions and holders told apart as their rows are, or by class and
 * identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeptSessions::class)]
final class KeptSessionsTest extends TestCase
{
    /** @var string A second connection to the test database. */
    private const string ELSEWHERE = 'elsewhere';

    /**
     * The floor is the call's start until a revocation kept the session, then
     * the latest cutoff such a revocation moved, never earlier than the call's
     * start.
     *
     * @return void
     */
    public function testTheFloorIsTheLatestKeptCutoffOrTheCallsStart(): void
    {
        $kept    = new KeptSessions;
        $session = self::sessionWithKey(1);
        $member  = self::member(1);
        $began   = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        self::assertSame($began, $kept->floor($session, $member, $began));

        $kept->keep($session, $member, $began->addSecond());
        $kept->keep($session, $member, $began->subSeconds(5));

        self::assertSame($began->addSecond()->getTimestamp(), $kept->floor($session, $member, $began)->getTimestamp());

        $kept->keep($session, $member, $began->addSeconds(2));

        self::assertSame($began->addSeconds(2)->getTimestamp(), $kept->floor($session, $member, $began)->getTimestamp());
        self::assertSame($began->addSeconds(3)->getTimestamp(), $kept->floor($session, $member, $began->addSeconds(3))->getTimestamp());
    }

    /**
     * Sessions and holders that are Eloquent models are told apart as their
     * rows are: another key, the same key in another table, or the same key on
     * another connection is another; another instance of the same row is the
     * same.
     *
     * @return void
     */
    public function testModelsAreToldApartAsTheirRowsAre(): void
    {
        $kept   = new KeptSessions;
        $began  = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $cutoff = $began->addSecond();

        $kept->keep(self::sessionWithKey(1), self::member(1), $cutoff);

        self::assertSame($cutoff->getTimestamp(), $kept->floor(self::sessionWithKey(1), self::member(1), $began)->getTimestamp());
        self::assertSame($began, $kept->floor(self::sessionWithKey(2), self::member(1), $began));
        self::assertSame($began, $kept->floor(self::sessionWithKey(1)->setConnection(self::ELSEWHERE), self::member(1), $began));
        self::assertSame($began, $kept->floor(self::sessionWithKey(1), self::member(2), $began));
        self::assertSame($began, $kept->floor(self::sessionWithKey(1), self::member(1)->setConnection(self::ELSEWHERE), $began));
        self::assertSame($began, $kept->floor(self::sessionWithKey(1), (new RecheckedMembership)->forceFill(['id' => 1]), $began));
    }

    /**
     * A holder that is no Eloquent model is told apart by its class and its
     * identifier, as an identity or as a principal, and any other holder by the
     * instance itself.
     *
     * @return void
     */
    public function testHoldersThatAreNoModelAreToldApartByClassAndIdentifier(): void
    {
        $kept    = new KeptSessions;
        $session = self::sessionWithKey(1);
        $began   = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $cutoff  = $began->addSecond();
        $other   = self::holder();
        $held    = self::holder();

        $kept->keep($session, new PlainCutoffIdentity('7'), $cutoff);
        $kept->keep($session, new PlainCutoffPrincipal('8'), $cutoff);
        $kept->keep($session, $held, $cutoff);

        self::assertSame($cutoff->getTimestamp(), $kept->floor($session, new PlainCutoffIdentity(7), $began)->getTimestamp());
        self::assertSame($began, $kept->floor($session, new PlainCutoffIdentity(8), $began));
        self::assertSame($cutoff->getTimestamp(), $kept->floor($session, new PlainCutoffPrincipal(8), $began)->getTimestamp());
        self::assertSame($began, $kept->floor($session, new PlainCutoffPrincipal(7), $began));
        self::assertSame($cutoff->getTimestamp(), $kept->floor($session, $held, $began)->getTimestamp());
        self::assertSame($began, $kept->floor($session, $other, $began));
    }

    /**
     * Add a second connection to the test database.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('database.connections.' . self::ELSEWHERE, $config->get('database.connections.' . $config->string('database.default')));
    }

    /**
     * A session with the key, never saved.
     *
     * @param  int  $id
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private static function sessionWithKey(int $id): Session
    {
        return (new Session)->forceFill(['id' => $id]);
    }

    /**
     * A member with the key, never saved.
     *
     * @param  int  $id
     * @return \Tests\Integration\Fixtures\RecheckedMember
     */
    private static function member(int $id): RecheckedMember
    {
        return (new RecheckedMember)->forceFill(['id' => $id]);
    }

    /**
     * A holder that is neither an identity nor a principal.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter
     */
    private static function holder(): HasTokensValidAfter
    {
        return new class implements HasTokensValidAfter {
            /**
             * Return no cutoff.
             *
             * @return ?\Carbon\CarbonInterface
             */
            #[\Override]
            public function getTokensValidAfter(): ?CarbonInterface
            {
                return null;
            }

            /**
             * Move nothing.
             *
             * @param  \Carbon\CarbonInterface  $time
             * @return bool
             *
             * @imperative
             */
            #[\Override]
            public function invalidateTokensIssuedBefore(CarbonInterface $time): bool
            {
                unset($time);

                return false;
            }
        };
    }
}
