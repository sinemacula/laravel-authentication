<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\DeviceKeyShape;

/**
 * An identity's devices as the session service reads them: through the
 * identity's `devices()` relation, built inside `WriteConnection::during()` for
 * the identity and routed to the write connection, over a model that must be an
 * Eloquent `EloquentDevice` so its columns are known.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityDevices
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A write-connection query of the identity's devices, with the device model
     * it queries.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasDevices&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return array{0: \Illuminate\Contracts\Database\Eloquent\Builder, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice}
     *
     * @throws \LogicException
     */
    public static function query(HasDevices&Identity $identity): array
    {
        $query = WriteConnection::during($identity, static fn (): Builder => WriteConnection::query($identity->devices()));
        $model = $query->getModel();

        if (!$model instanceof EloquentDevice) {
            throw new \LogicException(sprintf('The devices() relation of %s must query a model that implements %s.', $identity::class, EloquentDevice::class));
        }

        return [$query, $model];
    }

    /**
     * The identity's device with the identifier, read on the write connection,
     * or `null` when the identity holds no devices, the identifier cannot be a
     * key of the device model (no query is made), or the identity has no such
     * device.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \LogicException
     */
    public static function find(Identity $identity, mixed $id): (EloquentDevice&Model)|null
    {
        if (!$identity instanceof HasDevices) {
            return null;
        }

        [$query, $model] = self::query($identity);

        if (!DeviceKeyShape::matches($model, $id)) {
            return null;
        }

        $device = WriteConnection::during($identity, static fn (): mixed => $query->find($id));

        return $device instanceof $model ? $device : null;
    }
}
