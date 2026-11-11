<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\Attributes\DeleteWhenMissingModels;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * Delivers the code that proves a change request's new identifier through the
 * application's `OneTimeCodeSender`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[DeleteWhenMissingModels]
final class SendIdentifierChangeCode implements ShouldBeEncrypted, ShouldQueue
{
    use InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $requestId
     */
    public function __construct(

        /** What the code is bound to: the change's guard, type, new identifier, identity and request. */
        public readonly CodeBinding $binding,

        /** The code, its issuance and its expiry. */
        public readonly IssuedCode $issued,

        /** The identity whose identifier the change would replace. */
        public readonly Identity&Model $identity,

        /** The change request the code proves. */
        public readonly string $requestId,
    ) {}

    /**
     * Send the code when it and its change request are still live.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function handle(Container $container): void
    {
        $now       = CarbonImmutable::now()->startOfSecond();
        $recipient = $this->recipient();

        if ($recipient === null || !$container->make(OneTimeCodes::class)->isCurrent($this->binding, $this->issued->issueId, $now)) {
            return;
        }

        $change = PendingChanges::live($recipient, $this->binding->type, $this->binding->guard, $now);

        if ($change === null || !hash_equals($change->request_id, $this->requestId)) {
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
        ));
    }

    /**
     * The identity, read again from the write connection, or `null` when it is
     * gone.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function recipient(): ?Identity
    {
        $identity = $this->identity;
        $fresh    = WriteConnection::during($identity, static fn (): ?Model => $identity->fresh());

        return $fresh instanceof Identity ? $fresh : null;
    }
}
