<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\CarbonInterface;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Records when, from which IP address and with which user agent a persisted
 * Eloquent session was last used, debounced by a configurable throttle.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecordSessionUsage
{
    /** @var int Fallback throttle window (seconds). */
    private const int DEFAULT_THROTTLE_SECONDS = 60;

    /**
     * Handle the SessionAuthenticated event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\SessionAuthenticated  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function __invoke(SessionAuthenticated $event): void
    {
        $session = self::sessionOf($event->context);

        if (!$session instanceof EloquentSession || !$session instanceof Model || !$session->exists) {
            return;
        }

        $now = Carbon::now();

        if (!$this->shouldRecord($session->getLastUsedAt(), $now)) {
            return;
        }

        $client = $event->context->client;

        $usage = [
            $session->getLastUsedAtName()        => $session->fromDateTime($now),
            $session->getLastUsedIpName()        => $client->ip,
            $session->getLastUsedUserAgentName() => $client->userAgent,
        ];

        $session->newQuery()
            ->whereKey($session->getKey())
            ->update($usage);

        $session->forceFill($usage)->syncOriginalAttributes(array_keys($usage));
    }

    /**
     * The session the event names, reusing the one its guard has bound, or
     * `null` for none.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private static function sessionOf(EventContext $context): ?Session
    {
        if ($context->sessionId === null) {
            return null;
        }

        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth  = Container::getInstance()->make('auth');
        $guard = $context->guard === null ? null : $auth->resolvedGuard($context->guard);
        $bound = $guard !== null && $guard->hasUser() ? $guard->session() : null;

        return $bound !== null && IdentifierCoercion::matches($bound->getSessionIdentifier(), $context->sessionId)
            ? $bound
            : SessionLookup::find($context->sessionId);
    }

    /**
     * Whether the use should be recorded now: on first use, or once the
     * throttle window has elapsed since the last recorded use.
     *
     * @param  ?\Carbon\CarbonInterface  $lastUsedAt
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     */
    private function shouldRecord(?CarbonInterface $lastUsedAt, CarbonInterface $now): bool
    {
        if ($lastUsedAt === null) {
            return true;
        }

        $windowSeconds = Config::integer(
            'authentication.session.last_used_throttle_seconds',
            self::DEFAULT_THROTTLE_SECONDS,
        );

        return $lastUsedAt->diffInSeconds($now, true) >= $windowSeconds;
    }
}
