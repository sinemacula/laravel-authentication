<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * What proves the caller authenticated recently enough for a sensitive change
 * of an identity (changing its email address or phone number): one of.
 *
 * - `session($session)`: the session it is making the change from, which must
 *   be one of the identity's own live sessions of the guard, signed in within
 *   the window (a refresh or a principal switch does not renew it; a fresh
 *   sign-in
 *   does, so an identity with no password reauthenticates that way);
 * - `password($password)`: the identity's current password, checked when the
 *   change is requested and counted against its sign-in limits;
 * - `confirmedAt($at)`: when a further factor, or any other proof the
 *   application verified itself, was confirmed, which must be within the window
 *   and not in the future. It is trusted, as `start()` trusts the identity it
 *   is given: never build it from a time the client sent.
 *
 * The window is the flow's own setting (for an identifier change,
 * `authentication.identifier_changes.recent_authentication_seconds`). The
 * password is held as a `\SensitiveParameterValue`, so no dump of the object
 * shows it and serialising it throws.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Reauthentication
{
    /**
     * Constructor.
     *
     * @param  \Carbon\CarbonImmutable|\SensitiveParameterValue|\SineMacula\Laravel\Authentication\Contracts\Session  $proof
     */
    private function __construct(

        /** The session the change is made from, the password given, or when the application confirmed a proof of its own. */
        private CarbonImmutable|\SensitiveParameterValue|Session $proof,
    ) {}

    /**
     * Proof by the session the change is made from: the session must have
     * signed in within the window.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return self
     */
    public static function session(Session $session): self
    {
        return new self($session);
    }

    /**
     * Proof by the identity's current password, checked now.
     *
     * @param  string  $password
     * @return self
     */
    public static function password(#[\SensitiveParameter] string $password): self
    {
        return new self(new \SensitiveParameterValue($password));
    }

    /**
     * Proof the application verified itself at the given time (a further
     * factor, say), which must be within the window and not in the future.
     *
     * @param  \Carbon\CarbonInterface  $at
     * @return self
     */
    public static function confirmedAt(CarbonInterface $at): self
    {
        return new self(CarbonImmutable::instance($at));
    }

    /**
     * Run the callback for the kind of proof this is, with what it carries, and
     * return what it returns.
     *
     * @template TResult
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Session): TResult  $session
     * @param  \Closure(string): TResult  $password
     * @param  \Closure(\Carbon\CarbonImmutable): TResult  $confirmedAt
     * @return TResult
     *
     * @param-immediately-invoked-callable  $session
     * @param-immediately-invoked-callable  $password
     * @param-immediately-invoked-callable  $confirmedAt
     *
     * @internal
     */
    public function apply(\Closure $session, \Closure $password, \Closure $confirmedAt): mixed
    {
        return match (true) {
            $this->proof instanceof Session                  => $session($this->proof),
            $this->proof instanceof \SensitiveParameterValue => $password($this->proof->getValue()),
            default                                          => $confirmedAt($this->proof),
        };
    }
}
