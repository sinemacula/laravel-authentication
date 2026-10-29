<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\Attributes\DeleteWhenMissingModels;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;

/**
 * Tells an identity's old identifier that a change replaced it, through the
 * application's `IdentifierChangeNotifier`, once the change has committed.
 *
 * The payload carries both identifiers, so it is encrypted with the application
 * key on the queue. The change stands whatever happens here: an exception from
 * the notifier fails the job and the application's retry policy applies, and an
 * unbound notifier is a `BindingResolutionException`. A job whose identity was
 * deleted before it ran is dropped, not failed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[DeleteWhenMissingModels]
final class SendIdentifierChangeNotice implements ShouldBeEncrypted, ShouldQueue
{
    use InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice  $notice
     */
    public function __construct(

        /** The committed change to tell the old identifier about. */
        public readonly IdentifierChangeNotice $notice,
    ) {}

    /**
     * Hand the notice to the application's notifier.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function handle(Container $container): void
    {
        $container->make(IdentifierChangeNotifier::class)->notify($this->notice);
    }
}
