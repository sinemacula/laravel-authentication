<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Callers;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;

/**
 * The credential a route reads its caller from, as its middleware declares it
 * on the request: the access credential of the default guard unless
 * `authentication.refresh` declares the refresh credential, or
 * `authentication.pending` the pending one for a pending action, each of the
 * guard it names or the default one. The declaration is never inferred from
 * what the request carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeclaredCredential
{
    /** @var string The request attribute the declaration is kept under. */
    private const string ATTRIBUTE = 'authentication.credential';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential  $credential
     * @param  ?string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     */
    private function __construct(

        /** The credential the route reads its caller from. */
        public CallerCredential $credential,

        /** Name of the guard the credential belongs to, or `null` for the default guard. */
        public ?string $guard,

        /** The pending action a pending credential must allow now, or `null` for any other credential. */
        public ?PendingAction $action,
    ) {}

    /**
     * The access credential of the default guard: what a route reads unless it
     * declares another.
     *
     * @return self
     */
    public static function access(): self
    {
        return new self(CallerCredential::ACCESS, null, null);
    }

    /**
     * The refresh credential of the guard, or of the default guard.
     *
     * @param  ?string  $guard
     * @return self
     */
    public static function refresh(?string $guard): self
    {
        return new self(CallerCredential::REFRESH, $guard, null);
    }

    /**
     * The pending credential of the guard, or of the default guard, for the
     * pending action named by its stable value.
     *
     * @param  string  $action
     * @param  ?string  $guard
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function pending(string $action, ?string $guard): self
    {
        $pending = PendingAction::tryFrom($action);

        if ($pending === null) {

            $actions = implode(', ', array_map(static fn (PendingAction $case): string => $case->value, PendingAction::cases()));

            throw new \InvalidArgumentException(sprintf('The authentication.pending middleware takes a pending action (%s); [%s] is not one.', $actions, $action));
        }

        return new self(CallerCredential::PENDING, $guard, $pending);
    }

    /**
     * The credential the request's route declared, or the default guard's
     * access credential when it declared none.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function of(Request $request): self
    {
        $declared = $request->attributes->get(self::ATTRIBUTE);

        return $declared instanceof self ? $declared : self::access();
    }

    /**
     * Declare the credential on the request. A route declares one: a second,
     * different declaration is a misconfiguration.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \LogicException
     */
    public function declareOn(Request $request): void
    {
        $declared = $request->attributes->get(self::ATTRIBUTE);

        if ($declared instanceof self && !$declared->isSameAs($this)) {
            throw new \LogicException('A route reads its caller from one credential: it declares authentication.refresh or authentication.pending once.');
        }

        $request->attributes->set(self::ATTRIBUTE, $this);
    }

    /**
     * Whether the other declaration is of the same credential, guard and
     * action.
     *
     * @param  self  $other
     * @return bool
     */
    private function isSameAs(self $other): bool
    {
        return [$this->credential, $this->guard, $this->action] === [$other->credential, $other->guard, $other->action];
    }
}
