<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Lets a three-dimensional identity resolve a hinted principal itself, in place
 * of `principals()->find($hint)`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ResolvesHintedPrincipal
{
    /**
     * Resolve the principal the hint names, among this identity's own
     * principals only.
     *
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveHintedPrincipal(mixed $hint): ?Principal;
}
