<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * How removing one of an identity's passkeys ended: removed by this call, with
 * the factor package's completion of the removal, if its gate answered one, or
 * not removed, because the identity has no passkey by that id for the guard's
 * relying party (none was ever stored, or it was removed already, concurrently
 * included).
 *
 * `completion` is set only for a removal, and is opaque to the package: the
 * factor package's own answer (for one, the judgement of the current session
 * again once a passkey factor is gone, carrying a new pending credential), for
 * the caller to hand to its client. A removal that is not made commits nothing
 * of the gate's, so its completion is dropped with it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyRemoval
{
    /**
     * Constructor.
     *
     * @param  bool  $removed
     * @param  ?object  $completion
     */
    private function __construct(

        /** Whether this call removed the passkey. */
        private bool $removed,

        /** The factor package's completion of the removal, opaque to the package, for a removal only. */
        public ?object $completion = null,
    ) {}

    /**
     * This call removed the passkey, the factor gate answering the completion
     * given, if any.
     *
     * @param  ?object  $completion
     * @return self
     */
    public static function removed(?object $completion = null): self
    {
        return new self(true, $completion);
    }

    /**
     * The identity has no passkey by that id for the guard's relying party, so
     * nothing was removed.
     *
     * @return self
     */
    public static function notRemoved(): self
    {
        return new self(false);
    }

    /**
     * Whether this call removed the passkey.
     *
     * @return bool
     */
    public function isRemoved(): bool
    {
        return $this->removed;
    }
}
