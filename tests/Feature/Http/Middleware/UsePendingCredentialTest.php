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
use SineMacula\Laravel\Authentication\Http\Middleware\UsePendingCredential;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use Symfony\Component\HttpFoundation\Response;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the `authentication.pending` middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsePendingCredential::class)]
final class UsePendingCredentialTest extends TestCase
{
    /**
     * The default guard's pending credential is declared and the default guard
     * left as it was.
     *
     * @return void
     */
    public function testDeclaresTheDefaultGuardsPendingCredentialForTheAction(): void
    {
        $request  = Request::create('/');
        $response = new Response('passed');

        $next    = static fn (Request $passed): Response => $passed === $request ? $response : new Response('another');
        $handled = app(UsePendingCredential::class)->handle($request, $next, 'choose_principal');

        self::assertSame($response, $handled);
        self::assertSame(CallerCredential::PENDING, DeclaredCredential::of($request)->credential);
        self::assertSame(PendingAction::CHOOSE_PRINCIPAL, DeclaredCredential::of($request)->action);
        self::assertNull(DeclaredCredential::of($request)->guard);
        self::assertSame('api', Auth::getDefaultDriver());
    }

    /**
     * A guard named is declared and made the default for the request.
     *
     * @return void
     */
    public function testDeclaresANamedGuardsPendingCredentialAndUsesIt(): void
    {
        $request = Request::create('/');

        app(UsePendingCredential::class)->handle($request, static fn (): Response => new Response, 'mfa.verify', 'admin');

        self::assertSame(PendingAction::VERIFY, DeclaredCredential::of($request)->action);
        self::assertSame('admin', DeclaredCredential::of($request)->guard);
        self::assertSame('admin', Auth::getDefaultDriver());
    }

    /**
     * An action that is not a pending action is refused before the request is
     * passed on.
     *
     * @return void
     */
    public function testAnActionThatIsNotAPendingActionIsRefused(): void
    {
        try {
            app(UsePendingCredential::class)->handle(Request::create('/'), static fn (): never => self::fail('The request was passed on.'), 'sign_in', 'admin');

            self::fail('An unknown action was declared.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('[sign_in] is not one.', $exception->getMessage());
        }

        self::assertSame('api', Auth::getDefaultDriver());
    }

    /**
     * Through its alias, the declaration precedes route binding even when
     * listed after `SubstituteBindings`.
     *
     * @return void
     */
    public function testTheAliasIsOrderedBeforeSubstituteBindings(): void
    {
        Route::bind('declared', static fn (string $value): string => $value . ':' . DeclaredCredential::of(request())->action?->value);

        Route::middleware([SubstituteBindings::class, 'authentication.pending:mfa.verify,admin'])
            ->get('/declared/{declared}', static fn (string $declared): array => ['declared' => $declared]);

        $this->getJson('/declared/value')->assertOk()->assertExactJson(['declared' => 'value:mfa.verify']);

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
