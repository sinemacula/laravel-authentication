<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Testing\Fakes\EventFake;
use Illuminate\Testing\TestResponse;
use Laravel\Octane\Events\RequestTerminated;
use Laravel\Octane\Octane;
use Laravel\Octane\OctaneServiceProvider;
use Laravel\Octane\RequestContext;
use Laravel\Octane\Testing\Fakes\FakeClient;
use Laravel\Octane\Testing\Fakes\FakeWorker;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Tests\Integration\Octane\Fixtures\BootedApplicationFactory;

/**
 * Serves requests through one Laravel Octane worker, as Octane's own suite
 * does: the test's booted application, warmed with Octane's default services,
 * is the worker's root application, and every request runs through the real
 * `Worker`, which clones it into a sandbox and dispatches Octane's listeners
 * (the configuration sandbox, `FlushAuthenticationState`, the new request
 * instance, the flush of scoped instances) around the HTTP kernel. Only the
 * server is fake: no Swoole, RoadRunner or FrankenPHP.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ServesRequestsThroughOctane
{
    /** @var ?\Laravel\Octane\Testing\Fakes\FakeWorker The worker every request is served by. */
    private ?FakeWorker $octaneWorker = null;

    /** @var ?\Laravel\Octane\Testing\Fakes\FakeClient The fake server the worker answers. */
    private ?FakeClient $octaneClient = null;

    /** @var list<array{0: \Illuminate\Support\Testing\Fakes\EventFake, 1: list<class-string>}> Each recording dispatcher a request bound, with the classes it records. */
    private array $requestRecorders = [];

    /**
     * Register Octane on the test's application, warm it as a worker does at
     * boot, and boot a worker on it.
     *
     * @return void
     */
    protected function bootOctaneWorker(): void
    {
        $app = $this->octaneApplication();

        $app->register(OctaneServiceProvider::class);

        $factory = new BootedApplicationFactory($app);

        $this->octaneClient = new FakeClient([]);
        $this->octaneWorker = new FakeWorker($factory, $this->octaneClient);

        $this->octaneWorker->boot();
    }

    /**
     * Serve the request through the worker and return its response, failing the
     * test when the worker itself caught an error.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function serve(Request $request): TestResponse
    {
        $worker = $this->octaneWorker;
        $client = $this->octaneClient;

        self::assertNotNull($worker, 'Boot the Octane worker before serving a request.');
        self::assertNotNull($client);

        $errors    = count($client->errors);
        $responses = count($client->responses);

        $worker->handle($request, new RequestContext(['request' => $request]));

        self::assertSame([], array_slice($client->errors, $errors), 'The Octane worker caught an error.');
        self::assertCount($responses + 1, $client->responses);

        $response = $client->responses[$responses];

        $this->restoreRootApplication($request, $response);

        return TestResponse::fromBaseResponse($response);
    }

    /**
     * A JSON request from a client, with a bearer token or none, and any other
     * server variables given.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  array<string, mixed>  $parameters
     * @param  ?string  $bearer
     * @param  string  $ip
     * @param  array<string, string>  $server
     * @return \Illuminate\Http\Request
     */
    protected static function octaneRequest(string $method, string $uri, array $parameters = [], ?string $bearer = null, string $ip = '203.0.113.7', array $server = []): Request
    {
        $server = ['REMOTE_ADDR' => $ip, 'HTTP_ACCEPT' => 'application/json', 'HTTP_USER_AGENT' => 'OctaneTest/1.0', ...$server];

        if ($bearer !== null) {
            $server['HTTP_AUTHORIZATION'] = 'Bearer ' . $bearer;
        }

        return Request::create($uri, $method, $parameters, server: $server);
    }

    /**
     * What the named guard has bound for the request being served: the
     * identity, principal, device and tenant identifiers, and the granted
     * scopes.
     *
     * @param  string  $guard
     * @return array{identity: mixed, principal: mixed, device: mixed, tenant: mixed, scopes: ?list<string>}
     */
    protected static function contextOf(string $guard): array
    {
        $resolved = Auth::manager()->guard($guard);

        self::assertInstanceOf(ContextualGuard::class, $resolved);

        return [
            'identity'  => $resolved->identity()?->getAuthIdentifier(),
            'principal' => $resolved->principal()?->getPrincipalIdentifier(),
            'device'    => $resolved->device()?->getDeviceIdentifier(),
            'tenant'    => $resolved->tenant()?->getTenantIdentifier(),
            'scopes'    => $resolved->scopes(),
        ];
    }

    /**
     * Bind, as the events of the application now serving, a dispatcher that
     * records the events of the classes given and passes every other on, as
     * `Event::fake()` does, for this request's sandbox alone: the next request
     * is cloned from the booted application, with its own dispatcher.
     *
     * @param  list<class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>>  $classes
     * @return void
     */
    protected function recordInThisRequest(array $classes): void
    {
        $fake = new EventFake(app(Dispatcher::class), $classes);

        app()->instance('events', $fake);

        $this->requestRecorders[] = [$fake, $classes];
    }

    /**
     * What each request that bound a recording dispatcher has recorded by now,
     * in the order the requests were served: each event of the classes it
     * records, by class in the order given, as the event's short class name and
     * the IP address of the client its context names. An event a later request
     * dispatched to an earlier request's dispatcher shows up under the earlier
     * request.
     *
     * @return list<list<array{0: string, 1: ?string}>>
     */
    protected function eventsRecordedByEachRequest(): array
    {
        $recorded = [];

        foreach ($this->requestRecorders as [$fake, $classes]) {

            $events = [];

            foreach ($classes as $class) {
                foreach ($fake->dispatched($class) as [$event]) {

                    self::assertInstanceOf(AuthenticationEvent::class, $event);

                    $events[] = [class_basename($event), $event->context()->client->ip];
                }
            }

            $recorded[] = $events;
        }

        return $recorded;
    }

    /**
     * Hand the services Octane gave the request's sandbox (the auth and
     * database managers, the router, the HTTP kernel) back to the root
     * application, so the test can read the database and use the manager
     * between requests: the sandbox they hold has been flushed once the worker
     * is done with it. Only the application they hold is replaced, as the next
     * request's own listeners replace it again; nothing is reset, so the auth
     * manager keeps the guards the request resolved, and whatever the next
     * request does not see is down to Octane's lifecycle alone.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @return void
     */
    private function restoreRootApplication(Request $request, Response $response): void
    {
        $app   = $this->octaneApplication();
        $event = new RequestTerminated($app, $app, $request, $response);

        foreach (Octane::prepareApplicationForNextOperation() as $listener) {

            if (!str_contains($listener, 'GiveNewApplicationInstanceTo')) {
                continue;
            }

            $app->make($listener)->handle($event);
        }

        Auth::manager()->setApplication($app);
    }

    /**
     * The test's booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function octaneApplication(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        return $app;
    }
}
