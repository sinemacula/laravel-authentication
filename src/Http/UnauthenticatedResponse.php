<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\JsonResponse;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;

/**
 * Guest response for the package's guards.
 *
 * A request that fails authentication on a package guard answers `401` with a
 * JSON body, whatever its `Accept` header says, instead of Laravel's guest
 * redirect: the package's guards are stateless, so there is no login page to
 * send the client to. Registered as an exception-handler render callback, it
 * returns `null` for every other `AuthenticationException`, so other guards
 * keep Laravel's behaviour and render callbacks registered by the application
 * still take precedence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UnauthenticatedResponse
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     */
    public function __construct(

        /** Auth factory used to resolve the guards an exception names. */
        private AuthFactory $auth,
    ) {}

    /**
     * Render the `401` response for an exception raised by package guards, or
     * `null` to defer to Laravel.
     *
     * @param  \Illuminate\Auth\AuthenticationException  $exception
     * @return ?\Illuminate\Http\JsonResponse
     */
    public function __invoke(AuthenticationException $exception): ?JsonResponse
    {
        /** @var array<int, ?string> $guards */
        $guards = $exception->guards();

        if (!$this->appliesTo($guards)) {
            return null;
        }

        return new JsonResponse(['message' => $exception->getMessage()], JsonResponse::HTTP_UNAUTHORIZED);
    }

    /**
     * Whether every named guard is a package guard. A `null` name, or no names
     * at all, means the default guard, as for the `auth` middleware.
     *
     * @param  array<int, ?string>  $guards
     * @return bool
     */
    public function appliesTo(array $guards): bool
    {
        foreach ($guards === [] ? [null] : $guards as $guard) {
            if (!$this->auth->guard($guard) instanceof ContextualGuard) {
                return false;
            }
        }

        return true;
    }
}
