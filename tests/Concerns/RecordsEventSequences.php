<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;

/**
 * Records every authentication event a flow dispatches, in order, as one line
 * each: the event, the guard, what the event says happened (a failure's flow
 * and reason, a revocation's reason, how a session was signed into, the
 * principal a switch left, a password's flow) and the identity, principal and
 * device it concerns.
 *
 * The events recorded are every package event (one listener on the
 * `AuthenticationEvent` contract) and Laravel's `Attempting`, `Validated`,
 * `Login`, `Authenticated`, `Failed` and `Logout`, the only Laravel auth events
 * the package dispatches. A test names the identities, principals and devices
 * it expects (`i1`, `p1`, `d1`, ..., with `-` for none) before it records, so a
 * name in a line says which of them the event carried; a key the test did not
 * name takes the next name of its kind when it first appears (a device the flow
 * creates, or one it should not have carried), and keeps it from one flow to
 * the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsEventSequences
{
    /** @var list<string> The lines recorded since recording last began. */
    private array $sequence = [];

    /** @var array{identity: array<string, string>, principal: array<string, string>, device: array<string, string>} The name given to each key, by kind. */
    private array $names = ['identity' => [], 'principal' => [], 'device' => []];

    /** @var bool Whether the recording listeners are registered. */
    private bool $recording = false;

    /**
     * Start recording afresh, registering the listeners on first use.
     *
     * @return void
     */
    protected function recordSequence(): void
    {
        $this->sequence = [];

        if ($this->recording) {
            return;
        }

        $this->recording = true;

        $laravel = [Attempting::class, Validated::class, Login::class, Authenticated::class, Failed::class, Logout::class];

        Event::listen($laravel, function (Attempting|Authenticated|Failed|Login|Logout|Validated $event): void {
            $this->sequence[] = $this->laravelLine($event);
        });

        Event::listen(AuthenticationEvent::class, function (AuthenticationEvent $event): void {
            $this->sequence[] = $this->packageLine($event);
        });
    }

    /**
     * Name the identities `i1`, `i2`, ... in the order given, before any event
     * names them.
     *
     * @param  \Illuminate\Database\Eloquent\Model  ...$identities
     * @return void
     */
    protected function nameIdentities(Model ...$identities): void
    {
        foreach ($identities as $identity) {
            $this->nameOf('identity', $identity->getMorphClass(), self::keyOf($identity->getKey()));
        }
    }

    /**
     * Name the principals `p1`, `p2`, ... in the order given, before any event
     * names them.
     *
     * @param  \Illuminate\Database\Eloquent\Model  ...$principals
     * @return void
     */
    protected function namePrincipals(Model ...$principals): void
    {
        foreach ($principals as $principal) {
            $this->nameOf('principal', $principal->getMorphClass(), self::keyOf($principal->getKey()));
        }
    }

    /**
     * Name the devices `d1`, `d2`, ... in the order given, before any event
     * names them.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  ...$devices
     * @return void
     */
    protected function nameDevices(Device ...$devices): void
    {
        foreach ($devices as $device) {
            $this->nameOfDevice($device);
        }
    }

    /**
     * The name the device was given, or the next name of a device if it has
     * none yet: a device a flow created is named when an event first carries
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return string
     */
    protected function nameOfDevice(Device $device): string
    {
        return $this->nameOf('device', 'device', self::keyOf($device->getDeviceIdentifier()));
    }

    /**
     * The lines recorded since recording last began, in order.
     *
     * @return list<string>
     */
    protected function recordedSequence(): array
    {
        return $this->sequence;
    }

    /**
     * Describe one of Laravel's auth events: the event, the guard and, for all
     * but `Attempting`, the identity it carries.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Auth\Events\Attempting|\Illuminate\Auth\Events\Authenticated|\Illuminate\Auth\Events\Failed|\Illuminate\Auth\Events\Login|\Illuminate\Auth\Events\Logout|\Illuminate\Auth\Events\Validated  $event
     * @return string
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function laravelLine(Attempting|Authenticated|Failed|Login|Logout|Validated $event): string
    {
        $line = class_basename($event) . ' ' . $event->guard;

        return $event instanceof Attempting ? $line : $line . ' ' . $this->nameOfUser($event->user);
    }

    /**
     * Describe a package event: the event, the guard, what it says happened,
     * and the identity, principal and device of its context.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return string
     */
    private function packageLine(AuthenticationEvent $event): string
    {
        $context = $event->context();
        $detail  = $this->detailOf($event);

        return implode(' ', array_filter([
            class_basename($event),
            $context->guard ?? '-',
            $detail,
            $this->nameOfContext($context),
        ], static fn (?string $part): bool => $part !== null));
    }

    /**
     * What the event says happened, beyond its class (a switch's previous
     * principal, say): `null` when its class says it all.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return ?string
     */
    private function detailOf(AuthenticationEvent $event): ?string
    {
        return match (true) {
            $event instanceof PrincipalSwitched    => 'from:' . $this->nameOf('principal', $event->previousPrincipalMorphClass, $event->previousPrincipalId),
            $event instanceof AuthenticationFailed => $event->flow->value . ':' . $event->reason->value,
            $event instanceof DeviceRevoked        => $event->reason->value,
            $event instanceof SignedOutEverywhere  => $event->reason->value . ':' . $event->revoked,
            $event instanceof SignedIn             => $event->refresh ? 'refresh' : ($event->deviceCreated ? 'new' : 'continued'),
            $event instanceof PasswordSet          => $event->flow->value,
            default                                => null,
        };
    }

    /**
     * The names of the context's identity, principal and device.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return string
     */
    private function nameOfContext(EventContext $context): string
    {
        return implode('/', [
            $this->nameOf('identity', $context->identityMorphClass, $context->identityId),
            $this->nameOf('principal', $context->principalMorphClass, $context->principalId),
            $this->nameOf('device', 'device', $context->deviceId),
        ]);
    }

    /**
     * The name of the identity a Laravel event carries.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @return string
     */
    private function nameOfUser(?Authenticatable $user): string
    {
        return $this->nameOf('identity', $user instanceof Model ? $user->getMorphClass() : null, self::keyOf($user?->getAuthIdentifier()));
    }

    /**
     * The key as the event context records it.
     *
     * @param  mixed  $key
     * @return ?string
     */
    private static function keyOf(mixed $key): ?string
    {
        return is_int($key) || is_string($key) ? (string) $key : null;
    }

    /**
     * The name of the key of the kind, given on its first appearance.
     *
     * @param  'device'|'identity'|'principal'  $kind
     * @param  ?string  $type
     * @param  ?string  $id
     * @return string
     */
    private function nameOf(string $kind, ?string $type, ?string $id): string
    {
        if ($type === null || $id === null) {
            return '-';
        }

        $key = $type . '#' . $id;

        return $this->names[$kind][$key] ??= $kind[0] . (count($this->names[$kind]) + 1);
    }
}
