<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;

/**
 * Identifier change notifier contract.
 *
 * Tells the identifier an identity used to have (its old email address or phone
 * number) that it was replaced, through the application's own mail or SMS
 * gateway, so a change the owner did not make is noticed: the package ships no
 * notifier, and the application binds its implementation in the container.
 * `Auth::identifierChanges()` refuses to start or confirm a change while none
 * is bound.
 *
 * It is called only from a queued job, once the change has committed, and only
 * when the identity had an identifier of the type before. The change stands
 * whatever the notifier does: an exception it throws fails the job, and the
 * application's queue retry policy applies.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentifierChangeNotifier
{
    /**
     * Tell the notice's previous identifier that it was replaced.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice  $notice
     * @return void
     */
    public function notify(IdentifierChangeNotice $notice): void;
}
