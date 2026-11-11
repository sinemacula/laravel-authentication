<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * What proves the caller authenticated recently enough for a sensitive change
 * of an identity: the session it is made from, or its current password.
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
     * @param  \SensitiveParameterValue<string>|\SineMacula\Laravel\Authentication\Contracts\Session  $proof
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
     * Run the callback for the kind of proof this is, with what it carries.
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
