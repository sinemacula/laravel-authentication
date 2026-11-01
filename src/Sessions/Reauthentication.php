<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * What proves the caller authenticated recently enough for a sensitive change
 * of an identity (changing its email address or phone number): one of.
 *
 * - `session($session)`: the session it is making the change from, which must
 *   be one of the identity's own live sessions of the guard with a proof fresh
 *   enough for the operation (`identifier_change`, see `FreshnessPolicy`): its
 *   first factor, a reauthentication, a further factor or a recovery code, as
 *   the guard's freshness takes them, made within its age. A refresh or a
 *   principal switch records no proof, so neither renews it; a reauthentication
 *   or a step-up does.
 * - `password($password)`: the identity's current password, a reauthentication
 *   with the first factor made now, checked when the change is requested and
 *   counted against its sign-in limits; taken only when the guard's freshness
 *   for the operation takes a first-factor reauthentication and asks for
 *   neither multifactor authentication nor phishing resistance.
 *
 * A further factor the application verified itself proves nothing on its own:
 * record it on the session with the session service's `stepUp()`, and prove the
 * change with the session. The password is held as a
 * `\SensitiveParameterValue`, so no dump of the object shows it and serialising
 * it throws.
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
     * @param  \SensitiveParameterValue|\SineMacula\Laravel\Authentication\Contracts\Session  $proof
     */
    private function __construct(

        /** The session the change is made from, or the password given. */
        private \SensitiveParameterValue|Session $proof,
    ) {}

    /**
     * Proof by the session the change is made from: the session must hold a
     * proof fresh enough for the change.
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
     * Run the callback for the kind of proof this is, with what it carries, and
     * return what it returns.
     *
     * @template TResult
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Session): TResult  $session
     * @param  \Closure(string): TResult  $password
     * @return TResult
     *
     * @param-immediately-invoked-callable  $session
     * @param-immediately-invoked-callable  $password
     *
     * @internal
     */
    public function apply(\Closure $session, \Closure $password): mixed
    {
        return $this->proof instanceof Session ? $session($this->proof) : $password($this->proof->getValue());
    }
}
