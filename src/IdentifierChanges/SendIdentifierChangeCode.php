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
 * Delivers the code that proves the new identifier of a change request through
 * the application's `OneTimeCodeSender`, to that new identifier, outside the
 * request that asked for it.
 *
 * The payload carries the code and the identifier, so it is encrypted with the
 * application key on the queue. When the job runs it first checks, on the write
 * connection, that the code is still its binding's live issuance and that the
 * identity's pending change of the type is still this request, of this guard,
 * and sends nothing otherwise; a retry checks again, so the code of a change
 * that was confirmed, cancelled or replaced is never sent. It goes to the
 * identity it was issued for, read again from the write connection (the service
 * never changes a machine identity's identifiers), with the purpose
 * `change_identifier`. An exception from the sender fails the job, and the
 * application's retry policy applies. A job whose identity was deleted before
 * it ran is dropped, not failed.
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
            $this->issued->code,
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
