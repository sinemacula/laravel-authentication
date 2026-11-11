<?php

declare(strict_types = 1);

namespace Tests\Feature\Http\Middleware;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Middleware\UseRefreshCredential;
use Symfony\Component\HttpFoundation\Response;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the `authentication.refresh` middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UseRefreshCredential::class)]
final class UseRefreshCredentialTest extends TestCase
{
    /**
     * The default guard's refresh credential is declared and the default guard
     * left as it was.
     *
     * @return void
     */
    public function testDeclaresTheDefaultGuardsRefreshCredential(): void
    {
        $request  = Request::create('/');
        $response = new Response('passed');

        $handled = app(UseRefreshCredential::class)->handle($request, static fn (Request $passed): Response => $passed === $request ? $response : new Response('another'));

        self::assertSame($response, $handled);
        self::assertSame(CallerCredential::REFRESH, DeclaredCredential::of($request)->credential);
        self::assertNull(DeclaredCredential::of($request)->guard);
        self::assertSame('api', Auth::getDefaultDriver());
    }

    /**
     * A guard named is declared and made the default for the request.
     *
     * @return void
     */
    public function testDeclaresANamedGuardsRefreshCredentialAndUsesIt(): void
    {
        $request = Request::create('/');

        app(UseRefreshCredential::class)->handle($request, static fn (): Response => new Response, 'admin');

        self::assertSame('admin', DeclaredCredential::of($request)->guard);
        self::assertSame('admin', Auth::getDefaultDriver());
    }

    /**
     * Through its alias, the declaration precedes route binding even when
     * listed after `SubstituteBindings`.
     *
     * @return void
     */
    public function testTheAliasIsOrderedBeforeSubstituteBindings(): void
    {
        Route::bind('declared', static fn (string $value): string => $value . ':' . DeclaredCredential::of(request())->credential->value);

        Route::middleware([SubstituteBindings::class, 'authentication.refresh:admin'])
            ->get('/declared/{declared}', static fn (string $declared): array => ['declared' => $declared]);

        $this->getJson('/declared/value')->assertOk()->assertExactJson(['declared' => 'value:refresh']);

        self::assertSame('admin', Auth::getDefaultDriver());
    }

    /**
     * Register the guards the middleware names.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.defaults.guard', 'api');
    }
}
