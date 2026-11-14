<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\Attributes\DeleteWhenMissingModels;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Runtime\JwtGuardContexts;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Delivers a one-time code through the application's `OneTimeCodeSender`,
 * outside the request that asked for it.
 *
 * Every supported Laravel version reads the attribute, not the property.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[DeleteWhenMissingModels]
final class SendOneTimeCode implements ShouldBeEncrypted, ShouldQueue
{
    use InteractsWithQueue, Queueable, SerializesModels;

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

        /** The identity a verification or factor code is for; `null` for a sign-in code, whose recipient is found when the job runs. */
        public readonly ?Identity $identity = null,
    ) {}

    /**
     * Send the code when it is still live and its recipient may receive it.
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
        $purpose = self::deliverable($this->binding->purpose);

        if (!$container->make(OneTimeCodes::class)->isCurrent($this->binding, $this->issued->issueId, CarbonImmutable::now()->startOfSecond())) {
            return;
        }

        $recipient = match ($purpose) {
            CodePurpose::SIGN_IN      => $this->signInRecipient($container),
            CodePurpose::VERIFICATION => $this->verificationRecipient($container),
            default                   => $this->factorRecipient(),
        };

        if ($recipient === null) {
            return;
        }

        $container->make(OneTimeCodeSender::class)->send(new OneTimeCodeMessage(
            $this->binding->guard,
            $this->binding->purpose,
            $this->binding->type,
            $this->binding->identifier,
            $this->issued->secret(),
            $this->issued->expiresAt,
            $recipient,
            $this->binding->proofPurpose,
            $this->binding->factor,
        ));
    }

    /**
     * The purpose, when this job delivers its codes: a sign-in, a verification,
     * a further factor's or an enrolment's.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose
     *
     * @throws \LogicException
     */
    private static function deliverable(CodePurpose $purpose): CodePurpose
    {
        if (!in_array($purpose, [CodePurpose::SIGN_IN, CodePurpose::VERIFICATION, CodePurpose::MFA, CodePurpose::ENROLLMENT], true)) {
            throw new \LogicException(sprintf('%s delivers only sign-in, verification and factor codes, not [%s] codes.', self::class, $purpose->value));
        }

        return $purpose;
    }

    /**
     * The identity the guard's provider finds by the identifier, when it may
     * receive a sign-in code.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function signInRecipient(Container $container): ?Identity
    {
        $type     = $this->binding->type;
        $provider = JwtGuardContexts::named($container, $this->binding->guard, 'one-time codes')->provider();
        $found    = $provider->retrieveByCredentials([$type => $this->binding->identifier]);

        if (!$found instanceof Identity || !$found instanceof HasVerifiableIdentifiers || $found instanceof MachineIdentity) {
            return null;
        }

        return ActivationPolicy::isActive($found)
            && CodeIdentifiers::isHeldBy($found, $this->binding, $container->make(IdentifierVerifier::class))
            && WriteConnection::during($found, static fn (): bool => $found->hasVerifiedIdentifier($type)) ? $found : null;
    }

    /**
     * The identity the verification code was issued for, while it still holds
     * the bound identifier.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function verificationRecipient(Container $container): ?Identity
    {
        $fresh = $this->freshIdentity();

        if (!$fresh instanceof HasVerifiableIdentifiers || !$fresh instanceof Identity || $fresh instanceof MachineIdentity) {
            return null;
        }

        return CodeIdentifiers::isHeldBy($fresh, $this->binding, $container->make(IdentifierVerifier::class)) ? $fresh : null;
    }

    /**
     * The identity a further factor's or an enrolment's code was issued for,
     * read again from the write connection; never a machine identity.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function factorRecipient(): ?Identity
    {
        $fresh = $this->freshIdentity();

        return $fresh instanceof Identity && !$fresh instanceof MachineIdentity ? $fresh : null;
    }

    /**
     * The identity the code was issued for, read again from the write
     * connection when it is a model, or as given.
     *
     * @return mixed
     */
    private function freshIdentity(): mixed
    {
        $identity = $this->identity;

        return $identity instanceof Model ? WriteConnection::during($identity, static fn (): ?Model => $identity->fresh()) : $identity;
    }
}
