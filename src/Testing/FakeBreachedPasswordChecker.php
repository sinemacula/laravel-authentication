<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;

/**
 * A breached-password checker for tests: finds breached exactly the passwords
 * it is given, or, once made unavailable, cannot answer for any, and keeps
 * every password it was asked about, so a test can tell whether the policy
 * reached the breached check at all.
 *
 * `FakeBreachedPasswordChecker::fake(['password123'])` binds a fresh instance
 * as the application's checker and returns it. Assert on what it holds with the
 * test framework's own assertions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeBreachedPasswordChecker implements BreachedPasswordChecker
{
    /** @var list<string> The passwords asked about, oldest first. */
    private array $checked = [];

    /** @var bool Whether the checker throws as an unavailable service would. */
    private bool $unavailable = false;

    /**
     * Constructor.
     *
     * @param  list<string>  $breached
     */
    private function __construct(

        /** The passwords the checker finds breached. */
        private readonly array $breached,
    ) {}

    /**
     * Bind a fresh fake, which finds the given passwords breached, as the
     * checker in the container (the application's, when none is given) and
     * return it.
     *
     * @param  list<string>  $breached
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(array $breached = [], ?ContainerContract $container = null): self
    {
        $fake = new self($breached);

        ($container ?? Container::getInstance())->instance(BreachedPasswordChecker::class, $fake);

        return $fake;
    }

    /**
     * Keep the password, then say whether it is one of the breached ones, or
     * throw `BreachedPasswordCheckUnavailableException` while unavailable.
     *
     * @param  string  $password
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException
     */
    #[\Override]
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        $this->checked[] = $password;

        if ($this->unavailable) {
            throw new BreachedPasswordCheckUnavailableException('The breached-password service is unavailable.');
        }

        return in_array($password, $this->breached, true);
    }

    /**
     * Make the checker unable to answer, as a service that is down, or able
     * again.
     *
     * @param  bool  $unavailable
     * @return self
     */
    public function unavailable(bool $unavailable = true): self
    {
        $this->unavailable = $unavailable;

        return $this;
    }

    /**
     * The passwords asked about, oldest first, or those of them the filter
     * accepts.
     *
     * @param  (\Closure(string): bool)|null  $filter
     * @return list<string>
     */
    public function checked(?\Closure $filter = null): array
    {
        return $filter === null ? $this->checked : array_values(array_filter($this->checked, $filter));
    }

    /**
     * Whether any password was asked about, or any the filter accepts.
     *
     * @param  (\Closure(string): bool)|null  $filter
     * @return bool
     */
    public function hasChecked(?\Closure $filter = null): bool
    {
        return $this->checked($filter) !== [];
    }

    /**
     * How many passwords were asked about.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->checked);
    }

    /**
     * Forget every password asked about so far.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->checked = [];
    }
}
