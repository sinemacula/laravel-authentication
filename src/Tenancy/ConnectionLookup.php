<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

/**
 * The connection a session was established through, found on the first ask and
 * kept: the resolver runs at most once, however often the answer is read, and
 * not at all when nothing asks. It lives as long as the evaluation that made
 * it: `expire()` drops a resolver not yet run, so a lookup kept past the
 * evaluation cannot read whichever session holds the key by then. An answer
 * already found stays readable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConnectionLookup
{
    /** @var bool Whether the resolver has run. */
    private bool $resolved = false;

    /** @var ?string The connection the resolver found. */
    private ?string $connectionId = null;

    /** @var bool Whether the evaluation has ended with the resolver unrun. */
    private bool $expired = false;

    /**
     * Constructor.
     *
     * @param  ?\Closure(): ?string  $resolver
     */
    public function __construct(

        /** Finds the connection, or `null` when there is no way to find one. */
        private ?\Closure $resolver = null,
    ) {}

    /**
     * The connection, found on the first call.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function connectionId(): ?string
    {
        if (!$this->resolved && $this->expired) {
            throw new \LogicException('A tenant policy reads the session\'s connection while it answers, not after.');
        }

        if (!$this->resolved) {
            $this->connectionId = $this->resolver === null ? null : ($this->resolver)();
            $this->resolved     = true;
        }

        return $this->connectionId;
    }

    /**
     * End the evaluation: a connection not yet found is never found, and asking
     * for it throws; one already found stays readable.
     *
     * @return void
     */
    public function expire(): void
    {
        $this->expired  = true;
        $this->resolver = null;
    }
}
