<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Validation\Rules\Password;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;

/**
 * The password service of a JWT guard (`Auth::passwords($guard)`): the policy,
 * changes, establishments, resets and trusted sets.
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
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose passwords the service sets. */
        private GuardContext $context,

        /** Ends the sessions a change or a reset of a password ends. */
        private SessionRevocations $revocations,

        /** Container the settings, checker, hasher and handler are resolved from. */
        private Container $container,
    ) {}

    /**
     * The policy's verdict on a new password.
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
     * a form; `check()` and `set()` stay authoritative.
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
     * sessions its flow ends.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function set(Identity $identity, #[\SensitiveParameter] string $password, PasswordFlow $flow, ClientContext $client, ?Session $except = null): PasswordResult
    {
        $model = self::settable($identity, $flow, $except);
        $check = $this->check($password);

        if ($check->violations !== []) {
            return PasswordResult::rejected($check->violations);
        }

        $writer = new PasswordWriter($this->context, $this->revocations, $this->container);

        return PasswordResult::set($writer->write($model, $password, $flow, $client, $except));
    }

    /**
     * Change the signed-in identity's password given its current one, keeping
     * the session and ending every other.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $current
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Throwable
     */
    public function change(Session $session, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $password, ClientContext $client): PasswordResult
    {
        return (new PasswordChanges($this->context, $this->revocations, $this->container))->change($session, $current, $password, $client);
    }

    /**
     * Establish a first password for the signed-in identity, which has none,
     * keeping the session and ending every other.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Throwable
     */
    public function establish(Session $session, #[\SensitiveParameter] string $password, ClientContext $client): PasswordResult
    {
        return (new PasswordChanges($this->context, $this->revocations, $this->container))->establish($session, $password, $client);
    }

    /**
     * Send a password reset link to the identifier the input names, answering
     * the same whether or not anyone holds it.
     *
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function sendResetLink(#[\SensitiveParameter] array $input, ClientContext $client): CodeRequest
    {
        return (new ResetRequests($this->context, $this->container))->link($input, $client);
    }

    /**
     * Send a password reset code to the identifier the input names under the
     * type, as `sendResetLink()` sends a link.
     *
     * @param  string  $type
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function sendResetCode(string $type, #[\SensitiveParameter] array $input, ClientContext $client): CodeRequest
    {
        return (new ResetRequests($this->context, $this->container))->code($type, $input, $client);
    }

    /**
     * Reset the password with a link's token, from input read from the
     * request's body only.
     *
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     *
     * @throws \Throwable
     */
    public function reset(#[\SensitiveParameter] array $input, ClientContext $client): ResetResult
    {
        return (new ResetSubmissions($this->context, $this->revocations, $this->container))->link($input, $client);
    }

    /**
     * Reset the password with a code, from input read from the request's body
     * only.
     *
     * @param  string  $type
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     *
     * @throws \Throwable
     */
    public function resetWithCode(string $type, #[\SensitiveParameter] array $input, ClientContext $client): ResetResult
    {
        return (new ResetSubmissions($this->context, $this->revocations, $this->container))->code($type, $input, $client);
    }

    /**
     * The identity as a model whose password the flow may set.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function settable(Identity $identity, PasswordFlow $flow, ?Session $except): Identity&Model
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
            throw new \InvalidArgumentException(sprintf('A session to keep signed in is for a change of password, not a %s.', $flow->value));
        }

        if ($flow === PasswordFlow::ESTABLISHMENT) {
            throw new \InvalidArgumentException('A first password is established with establish(), which needs a recent authentication on the session.');
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
