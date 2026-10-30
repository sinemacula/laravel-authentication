<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when an identity's identifier of a type (its email address, its
 * phone number) is replaced by one it proved, once the change is committed on
 * the identity's connection: at once when that connection has no open
 * transaction, after its transaction commits otherwise, and never for a change
 * that is rolled back.
 *
 * The context carries the guard the change was made through, the identity and
 * the client that confirmed it. The identifiers are snapshots, so a queued
 * audit listener needs no query back: `previous` as it was stored (`null` when
 * the identity had none) and `identifier` in its normal form; neither is a
 * secret. It carries no code, link or token. The new identifier is verified by
 * the change itself, so no `IdentifierVerified` follows.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChanged implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $type
     * @param  ?string  $previous
     * @param  string  $identifier
     * @param  \Carbon\CarbonImmutable  $changedAt
     */
    public function __construct(

        /** The identity whose identifier changed, and the client that confirmed it. */
        public EventContext $context,

        /** Type of the identifier, for example `email`. */
        public string $type,

        /** The identifier replaced, as it was stored, or `null` when there was none. */
        public ?string $previous,

        /** The identifier that replaced it, in its normal form. */
        public string $identifier,

        /** When the change was made. */
        public CarbonImmutable $changedAt,
    ) {}

    /**
     * Return the identity whose identifier changed.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
