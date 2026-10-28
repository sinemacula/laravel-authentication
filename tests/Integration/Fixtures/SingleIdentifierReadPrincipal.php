<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D principal whose identifier can be read only a set number of times (once by
 * default), so a refresh fails part of the way through: past its check that the
 * device records the principal, while issuing the access token or the refresh
 * token.
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

    /** @var int Number of reads that succeed before every later one fails. */
    public int $readsAllowed = 1;

    /**
     * Return the identifier on the allowed reads and fail on every later one.
     *
     * @return mixed
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function getPrincipalIdentifier(): mixed
    {
        if (++$this->identifierReads > $this->readsAllowed) {
            throw new \RuntimeException('The principal identifier cannot be read again.');
        }

        return parent::getPrincipalIdentifier();
    }
}
