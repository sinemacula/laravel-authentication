<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;

/**
 * Tells an identity's old identifier that it was replaced.
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
