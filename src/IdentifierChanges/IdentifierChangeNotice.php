<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A committed change of identifier to tell the old identifier about: what
 * `IdentifierChangeNotifier::notify()` is given.
 *
 * `previous` is the destination: the identifier the identity held when the
 * change was requested, exactly as it was stored. `identifier` is the one that
 * replaced it, in its normal form, for a message that names it (or, better,
 * only part of it). Neither is a secret, and no code, link or token is carried.
 * The identity survives queueing as Laravel's `SerializesModels` keeps a model:
 * it is fetched again, in its state then, when the notice is delivered.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeNotice
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $previous
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Carbon\CarbonImmutable  $changedAt
     */
    public function __construct(

        /** Guard the change was made through. */
        public string $guard,

        /** Type of the identifier, for example `email` or `phone`. */
        public string $type,

        /** Destination: the identifier replaced, as it was stored. */
        #[\SensitiveParameter] public string $previous,

        /** The identifier that replaced it, in its normal form. */
        #[\SensitiveParameter] public string $identifier,

        /** Identity whose identifier changed. */
        public Identity $identity,

        /** When the change was made. */
        public CarbonImmutable $changedAt,
    ) {}
}
