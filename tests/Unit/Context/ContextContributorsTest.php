<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\ContextContributors;

/**
 * Unit tests for the registry of authentication context contributors: each
 * namespace taken once, in the order registered; the package's own namespace, a
 * malformed one and a second registration of one all refused loudly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextContributors::class)]
final class ContextContributorsTest extends TestCase
{
    /**
     * Nothing is registered until something registers, and then each
     * namespace's abstract is held in the order registered, a namespace of a
     * lower-case letter and 31 more characters included.
     *
     * @return void
     */
    public function testContributorsAreHeldInTheOrderRegistered(): void
    {
        $contributors = new ContextContributors;
        $longest      = 'a' . str_repeat('b_9', 10) . 'c';

        self::assertSame([], $contributors->registered());

        $contributors->register('sso', 'App\SsoContributor');
        $contributors->register('mfa', 'App\MfaContributor');
        $contributors->register($longest, 'App\LongContributor');

        self::assertSame(['sso' => 'App\SsoContributor', 'mfa' => 'App\MfaContributor', $longest => 'App\LongContributor'], $contributors->registered());
    }

    /**
     * Rows of `[namespace]`: each one no contributor may be registered under.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedNamespaces(): iterable
    {
        yield 'the package\'s own' => ['authentication'];
        yield 'empty' => [''];
        yield 'upper case' => ['Sso'];
        yield 'a leading digit' => ['1sso'];
        yield 'a leading underscore' => ['_sso'];
        yield 'a dot' => ['sso.keys'];
        yield 'a hyphen' => ['single-sign-on'];
        yield 'a trailing newline' => ["sso\n"];
        yield 'too long' => ['a' . str_repeat('b', 32)];
    }

    /**
     * A namespace that is the package's own or is not a lower-case letter and
     * then up to 31 lower-case letters, digits or underscores is refused, and
     * nothing is registered.
     *
     * @param  string  $namespace
     * @return void
     */
    #[DataProvider('provideRefusedNamespaces')]
    public function testANamespaceOutOfFormOrThePackagesIsRefused(string $namespace): void
    {
        $contributors = new ContextContributors;

        try {
            $contributors->register($namespace, 'App\Contributor');
            self::fail('The namespace was registered.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'An authentication context contributor cannot be registered under [' . $namespace . ']: a namespace is a lower-case letter'
                . ' and then up to 31 lower-case letters, digits or underscores, and not the package\'s own [authentication].',
                $exception->getMessage(),
            );
        }

        self::assertSame([], $contributors->registered());
    }

    /**
     * A namespace is taken once: a second registration fails loudly, naming the
     * one already registered, and leaves it in place.
     *
     * @return void
     */
    public function testANamespaceIsTakenOnce(): void
    {
        $contributors = new ContextContributors;

        $contributors->register('sso', 'App\SsoContributor');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An authentication context contributor is already registered under [sso]: App\SsoContributor.');

        try {
            $contributors->register('sso', 'App\OtherContributor');
        } finally {
            self::assertSame(['sso' => 'App\SsoContributor'], $contributors->registered());
        }
    }
}
