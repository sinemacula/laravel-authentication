<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Delivers a one-time code through the application's `OneTimeCodeSender`,
 * outside the request that asked for it, so the request's response and timing
 * say nothing about whether anyone has the identifier.
 *
 * The payload carries the code and the identifier, so it is encrypted with the
 * application key on the queue. When the job runs it first checks, on the write
 * connection, that the code is still the binding's live issuance (not replaced
 * by a resend, even one that drew the same digits, not used, not expired), and
 * sends nothing otherwise; a retry checks again, so a code that stopped working
 * is never sent. Then it finds the recipient. A sign-in code goes only to an
 * identity the guard's provider finds by the identifier that is active, can
 * report its identifiers verified, reports this one verified, and is not a
 * machine identity; for anyone else, or no one, nothing is sent and nothing
 * says so. A verification code goes only to the identity it was issued for,
 * read again from the write connection, while its identifier of the type is
 * still the one the code is bound to, and never to a machine identity. An
 * exception from the sender fails the job, and the application's retry policy
 * applies; an unbound sender is a `BindingResolutionException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SendOneTimeCode implements ShouldBeEncrypted, ShouldQueue
{
    use InteractsWithQueue, Queueable, SerializesModels;

    /** @var bool Drop the job, rather than fail it, when the identity it carries has been deleted. */
    public readonly bool $deleteWhenMissingModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     */
    public function __construct(

        /** What the code is bound to. */
        public readonly CodeBinding $binding,

        /** The code, its issuance and its expiry. */
        public readonly IssuedCode $issued,

        /** The identity a verification code is for; `null` for a sign-in code, whose recipient is found when the job runs. */
        public readonly ?Identity $identity = null,
    ) {
        $this->deleteWhenMissingModels = true;
    }

    /**
     * Send the code when it is still live and its recipient may receive it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function handle(Container $container): void
    {
        if (!$container->make(OneTimeCodes::class)->isCurrent($this->binding, $this->issued->issueId, CarbonImmutable::now()->startOfSecond())) {
            return;
        }

        $recipient = $this->binding->purpose === CodePurpose::SIGN_IN ? $this->signInRecipient($container) : $this->verificationRecipient($container);

        if ($recipient === null) {
            return;
        }

        $container->make(OneTimeCodeSender::class)->send(new OneTimeCodeMessage(
            $this->binding->guard,
            $this->binding->purpose,
            $this->binding->type,
            $this->binding->identifier,
            $this->issued->code,
            $this->issued->expiresAt,
            $recipient,
        ));
    }

    /**
     * The identity the guard's provider finds by the identifier, when it may
     * receive a sign-in code: active, not a machine identity, and reporting the
     * identifier verified (read on the write connection).
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     */
    private function signInRecipient(Container $container): ?Identity
    {
        $guard = $container->make('auth')->guard($this->binding->guard);

        if (!$guard instanceof JwtGuard) {
            throw new \InvalidArgumentException(sprintf('Auth guard [%s] is not a jwt guard, so it sends no one-time codes.', $this->binding->guard));
        }

        $type  = $this->binding->type;
        $found = $guard->getProvider()->retrieveByCredentials([$type => $this->binding->identifier]);

        if (!$found instanceof Identity || !$found instanceof HasVerifiableIdentifiers || $found instanceof MachineIdentity) {
            return null;
        }

        return ActivationPolicy::isActive($found) && WriteConnection::during($found, static fn (): bool => $found->hasVerifiedIdentifier($type)) ? $found : null;
    }

    /**
     * The identity the verification code was issued for, read again from the
     * write connection, while its identifier of the type is still the one the
     * code is bound to; never a machine identity.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function verificationRecipient(Container $container): ?Identity
    {
        $identity = $this->identity;
        $fresh    = $identity instanceof Model ? WriteConnection::during($identity, static fn (): ?Model => $identity->fresh()) : $identity;

        if (!$fresh instanceof HasVerifiableIdentifiers || $fresh instanceof MachineIdentity) {
            return null;
        }

        $type       = $this->binding->type;
        $current    = WriteConnection::during($fresh, static fn (): ?string => $fresh->getIdentifierForVerification($type));
        $identifier = $current === null ? null : $container->make(IdentifierVerifier::class)->canonical($type, $current);

        return $identifier !== null && hash_equals($this->binding->identifier, $identifier) ? $fresh : null;
    }
}
