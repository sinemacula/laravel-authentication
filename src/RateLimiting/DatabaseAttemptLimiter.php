<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;

/**
 * The package's attempt limiter, counting per identifier, account and IP
 * address in the `rate_limits` table on the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseAttemptLimiter implements AttemptLimiter
{
    /** @var list<string> First twelve bytes of the IPv4-mapped (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`) prefixes. */
    private const array IPV4_CARRYING_PREFIXES = ["\0\0\0\0\0\0\0\0\0\0\xff\xff", "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits  $limits
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\RateLimitStore  $store
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers  $normalizers
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\CounterKeys  $keys
     */
    public function __construct(

        /** Each guard's limits on each flow. */
        private AttemptLimits $limits,

        /** The counters. */
        private RateLimitStore $store,

        /** Normalisers that give identifiers their canonical form. */
        private IdentifierNormalizers $normalizers,

        /** The keys the counters are stored under. */
        private CounterKeys $keys,
    ) {}

    /**
     * Take a slot from each counter the subject counts against, giving them all
     * back when one is full.
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
     * limits.
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
     * The canonical form of an identifier: its type's normal form, otherwise
     * the value trimmed and lower-cased.
     *
     * @param  string  $identifier
     * @param  ?string  $type
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function canonicalIdentifier(#[\SensitiveParameter] string $identifier, ?string $type): string
    {
        $normalized = $type !== null && $this->normalizers->has($type) ? $this->normalizers->get($type)->normalize($identifier) : null;

        return $normalized ?? mb_strtolower(trim(mb_scrub($identifier, 'UTF-8')), 'UTF-8');
    }

    /**
     * The canonical form of an IP address: the IPv4 address it carries, or the
     * /64 network of any other IPv6 address.
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
