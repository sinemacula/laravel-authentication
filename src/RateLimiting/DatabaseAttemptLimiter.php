<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;

/**
 * The package's attempt limiter: per guard and flow, one counter per identifier
 * and one per IP address, kept in the `rate_limits` table on the write
 * connection, so the limits hold across servers without a cache.
 *
 * A counter's key is a keyed digest of the guard, the flow, the scope and the
 * canonical identifier or IP address (see `CounterKeys`), so the table alone
 * gives neither back, however easily they could be guessed. The canonical
 * identifier is what the normaliser registered for its type returns, the same
 * form an identity is looked up by, so `Ben@x.com` and `ben@x.com` share a
 * counter; without a normaliser, or for a value it rejects, it is the trimmed,
 * lower-cased value with invalid UTF-8 replaced. An IPv6 address is counted by
 * its /64 network, and one that carries an IPv4 client's address (IPv4-mapped,
 * or translated through the NAT64 well-known prefix) as that IPv4 address.
 *
 * An account a subject names (the row an Eloquent identity is stored in, see
 * `AttemptSubject::$account`) gets a counter of its own, kept as given and
 * shared by every guard (its key leaves the guard out), which each guard holds
 * to its own identifier limit. A lookup can find one account by many
 * identifiers (a column collation that ignores accents, widths or invisible
 * characters, a list of values, a query closure, another column), and through
 * every guard whose provider returns it, so the account's one counter is what
 * bounds the guesses made at its secret: a guard with a lower limit stops at
 * its own, and one whose identifier limit is off neither checks nor counts it.
 *
 * Counts change only through single statements (see `RateLimitStore`), and
 * reservations record the window each slot came from, so concurrent attempts
 * never exceed a limit and giving a slot back never touches a later window.
 * Database errors propagate: a limiter that cannot count does not let attempts
 * through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseAttemptLimiter implements AttemptLimiter
{
    /** @var list<string> The first twelve bytes of the IPv6 prefixes whose last four carry an IPv4 client's address: IPv4-mapped (`::ffff:0:0/96`) and the NAT64 well-known prefix (`64:ff9b::/96`). */
    private const array IPV4_CARRYING_PREFIXES = ["\0\0\0\0\0\0\0\0\0\0\xff\xff", "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits  $limits
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\RateLimitStore  $store
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers  $normalisers
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\CounterKeys  $keys
     */
    public function __construct(

        /** Each guard's limits on each flow. */
        private AttemptLimits $limits,

        /** The counters. */
        private RateLimitStore $store,

        /** Normalisers that give identifiers their canonical form. */
        private IdentifierNormalisers $normalisers,

        /** The keys the counters are stored under. */
        private CounterKeys $keys,
    ) {}

    /**
     * Take a slot from each counter the subject counts against, in turn: the
     * identifier's, the account's, then the IP address's. When one is full,
     * every slot taken before it is given back, and the wait is until the full
     * counter's window, as stored, ends.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function acquire(AttemptSubject $subject): AttemptReservation
    {
        $now     = CarbonImmutable::now()->getTimestamp();
        $windows = [];

        foreach ($this->counters($subject) as $key => $limit) {

            $window = $this->store->take($key, $limit->max, $now, $limit->windowEnd($now));

            if (is_int($window)) {

                $this->giveBack($windows);

                return new AttemptReservation($subject, $window - $now);
            }

            $windows[$key] = $window;
        }

        return new AttemptReservation($subject, null, $windows);
    }

    /**
     * Give back each slot the reservation took, to the window it took it from.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     */
    #[\Override]
    public function release(AttemptReservation $reservation): void
    {
        $this->giveBack($reservation->windows);
    }

    /**
     * Read both counters in one query and report the wait until the later of
     * the full windows ends.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function blocked(AttemptSubject $subject): ?int
    {
        $limits = $this->counters($subject);

        if ($limits === []) {
            return null;
        }

        $now  = CarbonImmutable::now()->getTimestamp();
        $full = [];

        foreach ($this->store->read(array_keys($limits)) as $key => ['hits' => $hits, 'ends' => $ends]) {

            if ($ends <= $now || $hits < $limits[$key]->max) {
                continue;
            }

            $full[] = $ends;
        }

        return $full === [] ? null : max($full) - $now;
    }

    /**
     * Count the failure against each counter the subject counts against.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function recordFailure(AttemptSubject $subject): void
    {
        $now = CarbonImmutable::now()->getTimestamp();

        foreach ($this->counters($subject) as $key => $limit) {
            $this->store->record($key, $now, $limit->windowEnd($now));
        }
    }

    /**
     * The counters the subject's attempt counts against, by key, with their
     * limits: the identifier's when there is one and its limit is on, then the
     * account's (shared by every guard) under the guard's identifier limit,
     * then the IP address's likewise.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return array<string, \SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit>
     *
     * @throws \InvalidArgumentException
     */
    private function counters(AttemptSubject $subject): array
    {
        $limits   = $this->limits->for($subject->guard, $subject->flow);
        $counters = [];

        if ($subject->identifier !== null && $limits[AttemptLimits::PER_IDENTIFIER] !== null) {

            $identifier = $this->canonicalIdentifier($subject->identifier, $subject->identifierType);

            $counters[$this->keys->counter($subject->guard, $subject->flow, AttemptLimits::PER_IDENTIFIER, $identifier)] = $limits[AttemptLimits::PER_IDENTIFIER];
        }

        if ($subject->account !== null && $limits[AttemptLimits::PER_IDENTIFIER] !== null) {
            $counters[$this->keys->account($subject->flow, $subject->account)] = $limits[AttemptLimits::PER_IDENTIFIER];
        }

        if ($subject->ip !== null && $limits[AttemptLimits::PER_IP] !== null) {
            $counters[$this->keys->counter($subject->guard, $subject->flow, AttemptLimits::PER_IP, self::canonicalIp($subject->ip))] = $limits[AttemptLimits::PER_IP];
        }

        return $counters;
    }

    /**
     * The canonical form of an identifier: its type's normal form when a
     * normaliser is registered for the type and accepts the value, otherwise
     * the value trimmed and lower-cased, with invalid UTF-8 replaced.
     *
     * @param  string  $identifier
     * @param  ?string  $type
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function canonicalIdentifier(#[\SensitiveParameter] string $identifier, ?string $type): string
    {
        $normalised = $type !== null && $this->normalisers->has($type) ? $this->normalisers->get($type)->normalise($identifier) : null;

        return $normalised ?? mb_strtolower(trim(mb_scrub($identifier, 'UTF-8')), 'UTF-8');
    }

    /**
     * The canonical form of an IP address: an IPv4 address, or the IPv4 address
     * an IPv6 address carries (IPv4-mapped, or translated through the NAT64
     * well-known prefix, as a server reached only over IPv6 sees every IPv4
     * client), in dotted decimal; any other IPv6 address as the /64 network it
     * belongs to, since a single client is usually given a whole /64 and could
     * otherwise count each of its addresses separately. Anything that is not an
     * IP address is counted as given.
     *
     * @param  string  $ip
     * @return string
     */
    private static function canonicalIp(string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        if (in_array(substr($packed, 0, 12), self::IPV4_CARRYING_PREFIXES, true)) {
            $packed = substr($packed, 12);
        }

        return strlen($packed) === 4
            ? (string) inet_ntop($packed)
            : inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    /**
     * Give back the slots taken, each to its own window.
     *
     * @param  array<string, string>  $windows
     * @return void
     */
    private function giveBack(array $windows): void
    {
        foreach ($windows as $key => $window) {
            $this->store->giveBack($key, $window);
        }
    }
}
