<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;

/**
 * A one-time code sender for tests: keeps every message it is given instead of
 * delivering it, so a test can read the code a request sent and sign in with
 * it.
 *
 * `FakeOneTimeCodeSender::fake()` binds a fresh instance as the application's
 * sender and returns it. Delivery runs in the queued job, so the message
 * arrives when the job runs: at once on a `sync` connection once the response
 * is sent (`$this->app->terminate()` in a test), or when the test runs the
 * queued job. Assert on what it holds with the test framework's own assertions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeOneTimeCodeSender implements OneTimeCodeSender
{
    /** @var list<\SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage> The messages sent, oldest first. */
    private array $messages = [];

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

        ($container ?? Container::getInstance())->instance(OneTimeCodeSender::class, $fake);

        return $fake;
    }

    /**
     * Keep the message instead of delivering it.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(OneTimeCodeMessage $message): void
    {
        $this->messages[] = $message;
    }

    /**
     * The messages sent, oldest first, or those of them the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage): bool)|null  $filter
     * @return list<\SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage>
     */
    public function sent(?\Closure $filter = null): array
    {
        return $filter === null ? $this->messages : array_values(array_filter($this->messages, $filter));
    }

    /**
     * The code last sent to the identifier, as delivered (in its normal form),
     * for the purpose when one is given; `null` when none was.
     *
     * @param  string  $identifier
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @return ?string
     */
    public function lastCodeFor(string $identifier, ?CodePurpose $purpose = null): ?string
    {
        $sent = $this->sent(static fn (OneTimeCodeMessage $message): bool => $message->identifier === $identifier && ($purpose === null || $message->purpose === $purpose));

        return $sent === [] ? null : $sent[count($sent) - 1]->code;
    }

    /**
     * Whether any message was sent, or any the filter accepts.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage): bool)|null  $filter
     * @return bool
     */
    public function hasSent(?\Closure $filter = null): bool
    {
        return $this->sent($filter) !== [];
    }

    /**
     * How many messages were sent.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->messages);
    }

    /**
     * Forget every message sent so far.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->messages = [];
    }
}
