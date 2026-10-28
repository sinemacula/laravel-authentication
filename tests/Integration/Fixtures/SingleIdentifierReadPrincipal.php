<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D principal whose identifier can be read only once, so a refresh issues the
 * access token and then fails while issuing the refresh token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SingleIdentifierReadPrincipal extends StubPrincipal
{
    /** @var int Number of times the identifier has been read. */
    public int $identifierReads = 0;

    /**
     * Return the identifier on the first read and fail on every later one.
     *
     * @return mixed
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function getPrincipalIdentifier(): mixed
    {
        if (++$this->identifierReads > 1) {
            throw new \RuntimeException('The principal identifier can be read only once.');
        }

        return parent::getPrincipalIdentifier();
    }
}
