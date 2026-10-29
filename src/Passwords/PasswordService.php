<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Validation\Rules\Password;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;

/**
 * The password service of a JWT guard (`Auth::passwords($guard)`): the password
 * policy, and the one call a registration, a change or a reset makes to set a
 * password.
 *
 * `check()` gives the policy's verdict on a new password and `rule()` the
 * Laravel validation rule for a form. `set()` is a trusted call, as `login()`
 * is: the caller has decided the identity may have the password, and chooses
 * the flow on the server, never from input, since a registration ends no
 * session. Ask for a recent reauthentication (the current password, say) before
 * a change. It applies the policy, and only a password that passes is hashed
 * and stored (see `PasswordWriter`). The policy never applies to the automatic
 * rehash on sign-in.
 *
 * A non-human identity (`MachineIdentity`) has no password, so setting one is a
 * misconfiguration. The service keeps no state between calls: it reads the
 * guard and resolves the settings, checker, hasher and session service each
 * time.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordService
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard whose passwords the service sets. */
        private JwtGuard $guard,

        /** Container the settings, checker, hasher and handler are resolved from. */
        private Container $container,
    ) {}

    /**
     * The policy's verdict on a new password: its length and composition, and
     * the breached check once those pass.
     *
     * @param  string  $password
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function check(#[\SensitiveParameter] string $password): PasswordCheck
    {
        return $this->policy()->check($password);
    }

    /**
     * Laravel's `Password` rule with the configured length and composition, for
     * a form. It runs no breached check and cannot express bcrypt's 72-byte
     * ceiling: `check()` and `set()` stay authoritative.
     *
     * @return \Illuminate\Validation\Rules\Password
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function rule(): Password
    {
        return $this->policy()->rule();
    }

    /**
     * Set the identity's password, when it passes the policy, and end the
     * sessions its flow ends: a change every session but `$except` (the device
     * the change was made from, when the application keeps it signed in), a
     * reset every session, a registration none. `PasswordSet` follows once it
     * commits. A password that breaks the policy writes nothing and reports
     * nothing: the result says which rules it breaks.
     *
     * The identity must be an Eloquent model, stored already for a change or a
     * reset (only a registration may insert it), and `$except` is for a change
     * only.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function set(Identity $identity, #[\SensitiveParameter] string $password, PasswordFlow $flow, ?Device $except = null): PasswordResult
    {
        $model = self::settable($identity, $flow, $except);
        $check = $this->check($password);

        if ($check->violations !== []) {
            return PasswordResult::rejected($check->violations);
        }

        return PasswordResult::set((new PasswordWriter($this->guard, $this->container))->write($model, $password, $flow, $except));
    }

    /**
     * The identity as a model whose password the flow may set.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function settable(Identity $identity, PasswordFlow $flow, ?Device $except): Identity&Model
    {
        if ($identity instanceof MachineIdentity) {
            throw new \InvalidArgumentException(sprintf('%s is a machine identity: it has no password to set.', $identity::class));
        }

        if (!$identity instanceof Model) {
            throw new \LogicException(sprintf('%s is not an Eloquent model, so its password cannot be set.', $identity::class));
        }

        if (!$identity->exists && $flow !== PasswordFlow::REGISTRATION) {
            throw new \LogicException(sprintf('%s is not stored yet: only a registration may set the password of a new identity.', $identity::class));
        }

        if ($except !== null && $flow !== PasswordFlow::CHANGE) {
            throw new \InvalidArgumentException(sprintf('A device to keep signed in is for a change of password, not a %s.', $flow->value));
        }

        return $identity;
    }

    /**
     * The password policy.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordPolicy
     */
    private function policy(): PasswordPolicy
    {
        return new PasswordPolicy($this->container);
    }
}
