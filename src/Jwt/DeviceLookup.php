<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;

/**
 * Finds a device of the configured device model by its identifier, the way the
 * refresh exchange and the session service read a device named by a token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeviceLookup
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Return a new instance of the configured device model, which must satisfy
     * the Eloquent-backed `EloquentDevice` boundary.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function model(): EloquentDevice&Model
    {
        $class = Config::string('authentication.device.model', '');

        InvalidDeviceModelConfigurationException::validate($class);

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice */
        return new $class;
    }

    /**
     * Look a device up by its identifier, reading from the write connection so
     * a lagging replica cannot serve a stale digest or revocation state. The
     * lookup runs inside `WriteConnection::during()` for the device model, so
     * relations the device model eager-loads come from the writer too.
     *
     * An identifier that cannot be a key of the device model names no device
     * and is rejected without a query; database errors on a well-formed
     * identifier propagate.
     *
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function find(mixed $id): (EloquentDevice&Model)|null
    {
        $model = self::model();

        if (!DeviceKeyShape::matches($model, $id)) {
            return null;
        }

        $device = WriteConnection::during($model, static fn (): mixed => WriteConnection::query($model->newQuery())->find($id));

        return $device instanceof Model ? $device : null;
    }
}
