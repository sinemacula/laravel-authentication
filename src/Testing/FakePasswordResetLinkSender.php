<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

/**
 * A password reset link sender for tests: keeps every link it is given instead
 * of delivering it, so a test can read the token a request sent and reset the
 * password with it.
 *
 * `FakePasswordResetLinkSender::fake()` binds a fresh instance as the
 * application's sender and returns it. Delivery runs in the queued job, so the
 * link arrives when the job runs: on a `sync` connection, once the response is
 * sent (`$this->app->terminate()` in a test), or when the test runs the queued
 * job. Assert on what it holds with the test framework's own assertions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakePasswordResetLinkSender implements PasswordResetLinkSender
{
    /** @var list<\SineMacula\Laravel\Authentication\Passwords\PasswordResetLink> The links sent, oldest first. */
    private array $links = [];

    /**
     * Bind a fresh fake as the sender in the container (the application's, when
     * none is given) and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(PasswordResetLinkSender::class, $fake);

        return $fake;
    }

    /**
     * Keep the link instead of delivering it.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordResetLink  $message
     * @return void
     */
    #[\Override]
    public function send(PasswordResetLink $message): void
    {
        $this->links[] = $message;
    }

    /**
     * The links sent, oldest first, or those of them the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordResetLink): bool)|null  $filter
     * @return list<\SineMacula\Laravel\Authentication\Passwords\PasswordResetLink>
     */
    public function sent(?\Closure $filter = null): array
    {
        return $filter === null ? $this->links : array_values(array_filter($this->links, $filter));
    }

    /**
     * The token last sent to the identifier, as delivered (in its normal form);
     * `null` when none was.
     *
     * @param  string  $identifier
     * @return ?string
     */
    public function lastTokenFor(string $identifier): ?string
    {
        $sent = $this->sent(static fn (PasswordResetLink $link): bool => $link->identifier === $identifier);

        return $sent === [] ? null : $sent[count($sent) - 1]->token();
    }

    /**
     * Whether any link was sent, or any the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordResetLink): bool)|null  $filter
     * @return bool
     */
    public function hasSent(?\Closure $filter = null): bool
    {
        return $this->sent($filter) !== [];
    }

    /**
     * How many links were sent.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->links);
    }

    /**
     * Forget every link sent so far.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->links = [];
    }
}
