<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;

/**
 * The channel a proof was made over: its kind, and the destination or
 * credential reference it used, when it has one.
 *
 * The reference is the destination a code went to (an email address or an E.164
 * phone number, in its normal form), or a reference to the credential: for a
 * passkey, the package's own passkey row id (never the WebAuthn credential id,
 * which can run past a thousand bytes); for an external provider, the
 * connection id. It names personal data for a code, so a proof's stored
 * reference is hidden from serialisation and pruned with its session.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Channel
{
    /** @var int Longest reference kept, in characters: the column's length. */
    public const int REFERENCE_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $kind
     * @param  ?string  $reference
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The kind of channel. */
        public ChannelKind $kind,

        /** The destination or credential reference, when there is one. */
        #[\SensitiveParameter] public ?string $reference = null,
    ) {
        if ($reference !== null && ($reference === '' || mb_strlen($reference) > self::REFERENCE_MAX_LENGTH)) {
            throw new \InvalidArgumentException(sprintf('A channel reference must be from 1 to %d characters, or null for none.', self::REFERENCE_MAX_LENGTH));
        }
    }
}
