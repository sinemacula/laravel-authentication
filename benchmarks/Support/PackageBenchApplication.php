<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * An application with the package's own bindings, for the benchmarks of paths
 * that resolve the package's collaborators from the container (the audience
 * policy, the attempt limiter, the sign-in methods, the scope registry): the
 * service provider is registered, not booted, over the shared sqlite database,
 * a dispatcher, the package's shipped configuration (with a signing key, and a
 * credentials timebox short enough not to pad the paths timed) and the guards
 * given, and `PlainBenchHasher`, so a password check costs next to nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PackageBenchApplication
{
    /** @var string HS256 signing secret for benchmark tokens. */
    private const string SECRET = 'benchmark-package-secret-key-with-at-least-32-bytes!';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Build the application, the one the container and the facades resolve
     * from, with the guards and providers given.
     *
     * @param  array<string, array<string, mixed>>  $guards
     * @return \Illuminate\Foundation\Application
     */
    public static function create(array $guards): Application
    {
        BenchDatabase::boot();

        $app    = new Application(dirname(__DIR__, 2));
        $config = new ConfigRepository([
            'app'      => ['key' => 'base64:' . base64_encode('laravel-authentication bench key')],
            'auth'     => ['guards' => $guards],
            'database' => ['default' => BenchDatabase::CONNECTION],
            'hashing'  => ['rehash_on_login' => false],
        ]);

        $app->instance('config', $config);

        $events = new Dispatcher($app);
        $events->setTransactionManagerResolver(static fn (): null => null);

        $app->instance('db', BenchDatabase::connectionResolver());
        $app->instance('events', $events);
        $app->instance('hash', new PlainBenchHasher);

        $app->register(AuthenticationServiceProvider::class);

        $config->set([
            'authentication.device.model'                     => Device::class,
            'authentication.device.table'                     => 'devices',
            'authentication.jwt.keys'                         => ['bench' => self::SECRET],
            'authentication.jwt.active_kid'                   => 'bench',
            'authentication.jwt.algorithm'                    => 'HS256',
            'authentication.jwt.issuer'                       => null,
            'authentication.jwt.audience'                     => null,
            'authentication.timebox.credentials_microseconds' => 1,
        ]);

        Container::setInstance($app);
        Facade::setFacadeApplication($app);

        return $app;
    }
}
