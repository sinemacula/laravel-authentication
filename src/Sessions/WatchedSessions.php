<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Support\RowKey;

/**
 * The checks of the request or job still waiting to judge each session
 * (`AdmissionRecheck`), so a later switch or choice of the same session tells
 * them what it no longer acts as: a check judges only the principal and tenant
 * the session still acts as and in when it runs. Sessions are told apart as
 * their rows are (`RowKey`), since each call loads its own instance of one.
 *
 * One instance is shared through the container, scoped, so nothing one request
 * or job watches is seen by the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WatchedSessions
{
    /** @var array<string, array<int, \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck>> Per session, the checks waiting, in the order they began to. */
    private array $watching = [];

    /**
     * The checks waiting to judge the session, in the order they began to.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return array<int, \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck>
     */
    public function of(Model $session): array
    {
        return $this->watching[RowKey::of($session)] ?? [];
    }

    /**
     * Record that the check waits to judge the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $check
     * @return void
     */
    public function watch(Model $session, AdmissionRecheck $check): void
    {
        $this->watching[RowKey::of($session)][spl_object_id($check)] = $check;
    }

    /**
     * Record that the check no longer waits: it ran, or the write it was to
     * judge rolled back.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $check
     * @return void
     */
    public function forget(Model $session, AdmissionRecheck $check): void
    {
        unset($this->watching[RowKey::of($session)][spl_object_id($check)]);
    }
}
