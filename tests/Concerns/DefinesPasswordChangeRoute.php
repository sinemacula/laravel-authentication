<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * The password change route README.md documents, through a guard: a slot of the
 * guard's `sign_in` limits taken before the transaction, the current password
 * checked under the identity's row lock and the new one set while it is held,
 * and the slot given back once the current password was right.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DefinesPasswordChangeRoute
{
    /**
     * Define `PUT /password` behind the guard's `auth` middleware.
     *
     * @param  string  $guard
     * @return void
     */
    protected static function definePasswordChangeRoute(string $guard): void
    {
        Route::middleware("auth:{$guard}")->put('/password', static function (Request $request, AttemptLimiter $limiter) use ($guard): JsonResponse|Response {
            $passwords = Auth::passwords($guard);
            $identity  = Auth::identity();

            assert($identity instanceof Model);

            $email = (string) $identity->getAttribute('email');
            $slot  = $limiter->acquire(new AttemptSubject($guard, AttemptFlow::SIGN_IN, $email, 'email', $request->ip()));

            if (!$slot->granted()) {
                return response()->json(['message' => 'Too many attempts.'], 429);
            }

            $result = $identity->getConnection()->transaction(static function () use ($passwords, $identity, $guard, $email, $request): ?PasswordResult {
                $identity->newQuery()->lockForUpdate()->find($identity->getKey());

                if (!Auth::guard($guard)->validate(['email' => $email, 'password' => $request->string('current_password')->value()])) {
                    return null;
                }

                return $passwords->set($identity, $request->string('password')->value(), PasswordFlow::CHANGE, Auth::device());
            });

            if ($result === null) {
                return response()->json(['message' => 'The current password is wrong.'], 422);
            }

            $limiter->release($slot);

            return $result->isSet()
                ? response()->noContent()
                : response()->json(['violations' => array_map(static fn (PasswordViolation $violation): string => $violation->value, $result->violations)], 422);
        });
    }
}
