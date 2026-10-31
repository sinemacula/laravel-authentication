<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Runtime\JwtGuardContexts;

/**
 * Delivers a password reset link or code outside the request that asked for it,
 * so the request's response and timing say nothing about whether anyone holds
 * the identifier.
 *
 * The payload carries the token or code and the identifier, so it is encrypted
 * with the application key on the queue. When the job runs it first checks, on
 * the write connection, that the token or code is still the binding's live
 * issuance, and sends nothing otherwise; a retry checks again. Then it finds
 * the recipient (see `ResetRecipient`): for anyone else, or no one, nothing is
 * sent and nothing says so. A link goes through the bound
 * `PasswordResetLinkSender`, a code through the `OneTimeCodeSender` with the
 * purpose `password_reset`. An exception from a sender fails the job, and the
 * application's retry policy applies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SendPasswordReset implements ShouldBeEncrypted, ShouldQueue
{
    use InteractsWithQueue, Queueable;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     */
    public function __construct(

        /** What the token or code is bound to. */
        public readonly CodeBinding $binding,

        /** The token or code, its issuance and its expiry. */
        public readonly IssuedCode $issued,
    ) {}

    /**
     * Send the link or code when it is still live and its recipient may reset
     * its password.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function handle(Container $container): void
    {
        $binding = $this->binding;
        $context = self::guardContext($container, $binding);

        if (!$container->make(OneTimeCodes::class)->isCurrent($binding, $this->issued->issueId, CarbonImmutable::now()->startOfSecond())) {
            return;
        }

        $recipient = ResetRecipient::find($context->name(), $context->provider(), $binding, $container);

        if (!$recipient instanceof Identity) {
            return;
        }

        if ($binding->purpose === CodePurpose::PASSWORD_RESET_LINK) {

            $container->make(PasswordResetLinkSender::class)->send(
                new PasswordResetLink($binding->guard, $binding->type, $binding->identifier, $this->issued->code, $this->issued->expiresAt, $recipient),
            );

            return;
        }

        $container->make(OneTimeCodeSender::class)->send(
            new OneTimeCodeMessage($binding->guard, $binding->purpose, $binding->type, $binding->identifier, $this->issued->code, $this->issued->expiresAt, $recipient),
        );
    }

    /**
     * The context of the guard the reset was requested through, which must be a
     * jwt guard (see `JwtGuardContexts`), for a binding of a reset purpose.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Runtime\GuardContext
     *
     * @throws \LogicException
     */
    private static function guardContext(Container $container, CodeBinding $binding): GuardContext
    {
        if ($binding->purpose !== CodePurpose::PASSWORD_RESET && $binding->purpose !== CodePurpose::PASSWORD_RESET_LINK) {
            throw new \LogicException(sprintf('%s delivers only password reset links and codes, not [%s] codes.', self::class, $binding->purpose->value));
        }

        return JwtGuardContexts::named($container, $binding->guard, 'password resets');
    }
}
