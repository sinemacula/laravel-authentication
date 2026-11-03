<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A link the link contract found: the identity an external result maps to and
 * the link's own id, opaque to the package and compared exactly. A session
 * signed in through the link records the id with its provenance, so a
 * reauthentication through the provider must come through the very same link,
 * and the link's removal ends only its own sessions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalLink
{
    /** @var int Longest link id, in characters: the column's length. */
    public const int ID_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity the link maps the result to. */
        public Identity $identity,

        /** The link's own id, opaque and compared exactly. */
        public string $id,
    ) {
        if ($id === '' || mb_strlen($id) > self::ID_MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('An external link\'s id must be from 1 to %d characters.', self::ID_MAX_LENGTH));
        }
    }
}
