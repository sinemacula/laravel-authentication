<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Optional 3D identity capability: resolve a hinted principal directly.
 *
 * Lets identities short-circuit the default `principals()->find($hint)` path
 * when they can hydrate the acting principal more efficiently - for example
 * with tenant data preloaded. An identity relation set on the result is not
 * proof of ownership: the guard reads a pinned principal's owner from the
 * principal's own stored key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ResolvesHintedPrincipal
{
    /**
     * Resolve the principal identified by the supplied hint, among this
     * identity's own principals only: the hint can come from a caller, so a
     * lookup by the hint alone could return another identity's principal. The
     * default resolver runs it inside `WriteConnection::during()` for this
     * identity: model reads on any connection, and query-builder reads on this
     * identity's own connection when it is an Eloquent model, go to the write
     * connection; any other query-builder read must pin itself (see
     * `Database\WriteConnection`).
     *
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveHintedPrincipal(mixed $hint): ?Principal;
}
