<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * An identifier change notifier for tests: keeps every notice it is given
 * instead of delivering it, so a test can check that the old identifier was
 * told about a change.
 *
 * `FakeIdentifierChangeNotifier::fake()` binds a fresh instance as the
 * application's notifier and returns it. A notice is delivered by a queued job
 * once the change commits, so it arrives when the job runs: on a `sync`
 * connection, once the response is sent (`$this->app->terminate()` in a test),
 * or when the test runs the queued job. Assert on what it holds with the test
 * framework's own assertions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeIdentifierChangeNotifier implements IdentifierChangeNotifier
{
    /** @var list<\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice> The notices sent, oldest first. */
    private array $notices = [];

    /**
     * Bind a fresh fake as the notifier in the container (the application's,
     * when none is given) and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(IdentifierChangeNotifier::class, $fake);

        return $fake;
    }

    /**
     * Keep the notice instead of delivering it.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice  $notice
     * @return void
     */
    #[\Override]
    public function notify(IdentifierChangeNotice $notice): void
    {
        $this->notices[] = $notice;
    }

    /**
     * The notices sent, oldest first, or those of them the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice): bool)|null  $filter
     * @return list<\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice>
     */
    public function sent(?\Closure $filter = null): array
    {
        return $filter === null ? $this->notices : array_values(array_filter($this->notices, $filter));
    }

    /**
     * The notices sent about the identity's changes, oldest first: an Eloquent
     * identity is matched by its row (`Model::is()`: key, table and
     * connection), any other by its class and auth identifier, compared as
     * strings.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return list<\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice>
     */
    public function noticesFor(Identity $identity): array
    {
        return $this->sent(static fn (IdentifierChangeNotice $notice): bool => $identity instanceof Model && $notice->identity instanceof Model
            ? $identity->is($notice->identity)
            : $notice->identity::class === $identity::class && IdentifierCoercion::matches($notice->identity->getAuthIdentifier(), $identity->getAuthIdentifier()));
    }

    /**
     * Whether any notice was sent, or any the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice): bool)|null  $filter
     * @return bool
     */
    public function hasSent(?\Closure $filter = null): bool
    {
        return $this->sent($filter) !== [];
    }

    /**
     * How many notices were sent.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->notices);
    }

    /**
     * Forget every notice sent so far.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->notices = [];
    }
}
