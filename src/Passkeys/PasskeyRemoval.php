<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * How removing one of an identity's passkeys ended.
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
     * This call removed the passkey.
     *
     * @param  ?object  $completion
     * @return self
     */
    public static function removed(?object $completion = null): self
    {
        return new self(true, $completion);
    }

    /**
     * The identity has no passkey by that id, so nothing was removed.
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
