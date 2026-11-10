<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Console\ConfigurationChecks;
use SineMacula\Laravel\Authentication\Console\ConfigurationFinding;
use SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity;
use Tests\Fixtures\Console\FixedConfigurationCheck;

/**
 * Unit tests for the registry of configuration checks: registered once, in
 * order; run in a stable order whatever the checks answer; a check that fails
 * reported and the rest still run; messages cleaned of control characters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationChecks::class)]
final class ConfigurationChecksTest extends TestCase
{
    /**
     * Nothing is registered until something registers; a check registered twice
     * is held once, in the position it first had.
     *
     * @return void
     */
    public function testChecksAreHeldOnceInTheOrderRegistered(): void
    {
        $checks = new ConfigurationChecks;

        self::assertSame([], $checks->registered());

        $checks->register('b');
        $checks->register('a');
        $checks->register('b');

        self::assertSame(['b', 'a'], $checks->registered());
    }

    /**
     * With nothing registered nothing is found.
     *
     * @return void
     */
    public function testNothingRegisteredFindsNothing(): void
    {
        self::assertSame([], (new ConfigurationChecks)->findings(new Container, ['api']));
    }

    /**
     * Findings are in the order the checks were registered, then package-wide
     * first and the guards in the order checked (any other last), then the
     * order the check gave them; each check is asked the guards.
     *
     * @return void
     */
    public function testFindingsAreInAStableOrder(): void
    {
        $container = new Container;
        $first     = new FixedConfigurationCheck([
            ConfigurationFinding::error('F1 admin', 'admin'),
            ConfigurationFinding::warning('F2 other', 'other'),
            ConfigurationFinding::error('F3 api', 'api'),
            ConfigurationFinding::warning('F4 none'),
            ConfigurationFinding::error('F5 api', 'api'),
        ]);
        $second = new FixedConfigurationCheck([ConfigurationFinding::warning('S1 api', 'api')]);

        $container->instance('second', $second);
        $container->instance('first', $first);

        $checks = new ConfigurationChecks;

        $checks->register('first');
        $checks->register('second');

        $messages = array_map(static fn (ConfigurationFinding $finding): string => $finding->message, $checks->findings($container, ['api', 'admin']));

        self::assertSame(['F4 none', 'F3 api', 'F5 api', 'F1 admin', 'F2 other', 'S1 api'], $messages);
        self::assertSame(['api', 'admin'], $first->asked);
        self::assertSame(['api', 'admin'], $second->asked);
    }

    /**
     * A check that throws is an error naming its class and the exception's
     * class, not its message, and the checks after it still run.
     *
     * @return void
     */
    public function testAThrowingCheckIsReportedAndTheRestRun(): void
    {
        $container = new Container;

        $container->instance(FixedConfigurationCheck::class, new FixedConfigurationCheck([], new \RuntimeException('secret-value')));
        $container->instance('after', new FixedConfigurationCheck([ConfigurationFinding::warning('Still ran.')]));

        $checks = new ConfigurationChecks;

        $checks->register(FixedConfigurationCheck::class);
        $checks->register('after');

        $findings = $checks->findings($container, []);

        self::assertCount(2, $findings);
        self::assertSame(FindingSeverity::ERROR, $findings[0]->severity);
        self::assertNull($findings[0]->guard);
        self::assertSame(sprintf('The configuration check [%s] failed: RuntimeException.', FixedConfigurationCheck::class), $findings[0]->message);
        self::assertSame('Still ran.', $findings[1]->message);
    }

    /**
     * An error (not only an exception) a check throws is reported as well.
     *
     * @return void
     */
    public function testAnErrorACheckThrowsIsReported(): void
    {
        $container = new Container;

        $container->instance('broken', new FixedConfigurationCheck([], new \TypeError('x')));

        $checks = new ConfigurationChecks;

        $checks->register('broken');

        self::assertSame('The configuration check [broken] failed: TypeError.', $checks->findings($container, [])[0]->message);
    }

    /**
     * An abstract that does not resolve to a check, or one that does not
     * resolve at all, is an error naming it.
     *
     * @return void
     */
    public function testAnUnresolvableOrWrongCheckIsReported(): void
    {
        $container = new Container;

        $container->instance('wrong', new \stdClass);

        $checks = new ConfigurationChecks;

        $checks->register('wrong');
        $checks->register('Missing\Check');

        $messages = array_map(static fn (ConfigurationFinding $finding): string => $finding->message, $checks->findings($container, []));

        self::assertSame([
            'The configuration check [wrong] failed: LogicException.',
            'The configuration check [Missing\Check] failed: Illuminate\Contracts\Container\BindingResolutionException.',
        ], $messages);
    }

    /**
     * A check that answers something other than findings is reported.
     *
     * @return void
     */
    public function testAnAnswerThatIsNotFindingsIsReported(): void
    {
        $container = new Container;

        $container->instance('odd', new FixedConfigurationCheck(['text']));

        $checks = new ConfigurationChecks;

        $checks->register('odd');

        $findings = $checks->findings($container, []);

        self::assertCount(1, $findings);
        self::assertSame('The configuration check [odd] failed: LogicException.', $findings[0]->message);
    }

    /**
     * Control characters are removed from a message and a guard, and an empty
     * message is given a stand-in.
     *
     * @return void
     */
    public function testControlCharactersAreStripped(): void
    {
        $container = new Container;

        $container->instance('dirty', new FixedConfigurationCheck([
            ConfigurationFinding::error("Bad\x1b[31m setting\x00\r\n", "ap\x07i"),
            ConfigurationFinding::warning("\x1b"),
            ConfigurationFinding::warning('Kept', "\x1b"),
        ]));

        $checks = new ConfigurationChecks;

        $checks->register('dirty');

        $findings = $checks->findings($container, ['api']);

        self::assertSame('(no message)', $findings[0]->message);
        self::assertSame('Bad[31m setting', $findings[1]->message);
        self::assertSame('api', $findings[1]->guard);
        self::assertSame('Kept', $findings[2]->message);
        self::assertNull($findings[2]->guard);
    }

    /**
     * A message is cut to a thousand characters.
     *
     * @return void
     */
    public function testALongMessageIsCut(): void
    {
        $container = new Container;

        $container->instance('long', new FixedConfigurationCheck([ConfigurationFinding::error(str_repeat('a', 1001))]));

        $checks = new ConfigurationChecks;

        $checks->register('long');

        self::assertSame(str_repeat('a', 1000), $checks->findings($container, [])[0]->message);
    }
}
