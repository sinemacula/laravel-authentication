<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

/**
 * A password reset link sender for tests that keeps every link instead of
 * delivering it.
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
     * Bind a fresh fake as the sender in the container and return it.
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
     * The token last sent to the identifier, or `null` when none was.
     *
     * @param  string  $identifier
     * @return ?string
     */
    public function lastTokenFor(string $identifier): ?string
    {
        $sent = $this->sent(static fn (PasswordResetLink $link): bool => $link->identifier === $identifier);

        return $sent === [] ? null : $sent[count($sent) - 1]->token()->reveal();
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
