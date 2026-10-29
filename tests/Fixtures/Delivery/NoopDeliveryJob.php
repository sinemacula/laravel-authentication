<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Delivery;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;

/**
 * A queueable job that does nothing, to watch how a delivery is pushed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NoopDeliveryJob implements ShouldQueue
{
    use Queueable;

    /**
     * Do nothing.
     *
     * @return void
     */
    public function handle(): void {}
}
