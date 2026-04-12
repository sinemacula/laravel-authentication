<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Optional 3D identity capability: resolve a hinted principal directly.
 *
 * Lets identities short-circuit the default `principals()->find($hint)` path
 * when they can hydrate the acting principal more efficiently - for example
 * with tenant data preloaded and the inverse identity relation already set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
interface ResolvesHintedPrincipal
{
    /**
     * Resolve the principal identified by the supplied hint.
     *
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveHintedPrincipal(mixed $hint): ?Principal;
}
