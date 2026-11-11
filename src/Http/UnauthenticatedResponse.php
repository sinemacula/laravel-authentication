<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Http\JsonResponse;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;

/**
 * Guest response for the package's guards.
 *
 * The translator is resolved per render so that, under Octane, it is the
 * request sandbox's.
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

        $message = ConsumerMessages::translate(Container::getInstance()->make(Translator::class), $exception->getMessage());

        return new JsonResponse(['message' => $message], JsonResponse::HTTP_UNAUTHORIZED);
    }

    /**
     * Whether every named guard is a package guard, no names meaning the
     * default guard.
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
