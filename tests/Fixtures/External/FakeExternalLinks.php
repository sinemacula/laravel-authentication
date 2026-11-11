<?php

declare(strict_types = 1);

namespace Tests\Fixtures\External;

use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\External\ExternalLink;

/**
 * In-memory external identity links that match on connection, issuer and
 * subject exactly and record every lookup.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FakeExternalLinks implements ExternalIdentityLinks
{
    /** @var list<array{0: string, 1: string, 2: string}> The connection, issuer and subject of every lookup, in order. */
    public array $asked = [];

    /** @var list<array{0: string, 1: string, 2: string, 3: \SineMacula\Laravel\Authentication\External\ExternalLink}> The links made, each with its connection, issuer and subject. */
    private array $links = [];

    /** @var ?\Throwable What the next lookup throws, if anything. */
    private ?\Throwable $failure = null;

    /** @var ?\Closure(): void What the next lookup runs before it answers, if anything. */
    private ?\Closure $during = null;

    /**
     * Link the identity through the connection for the issuer and subject,
     * under the link id given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $linkId
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return $this
     */
    public function link(Identity $identity, string $linkId, string $connectionId, string $issuer, string $subject): self
    {
        $this->links[] = [$connectionId, $issuer, $subject, new ExternalLink($identity, $linkId)];

        return $this;
    }

    /**
     * Have the next lookup throw.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    public function failWith(\Throwable $failure): void
    {
        $this->failure = $failure;
    }

    /**
     * Have the next lookup run the callback before it answers, as if something
     * changed while the adapter held the result.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    public function whileAsked(\Closure $callback): void
    {
        $this->during = $callback;
    }

    /**
     * The link made through exactly the connection for exactly the issuer and
     * subject, or `null`.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     *
     * @throws \Throwable
     */
    #[\Override]
    public function find(string $connectionId, string $issuer, string $subject): ?ExternalLink
    {
        $this->asked[] = [$connectionId, $issuer, $subject];

        if ($this->failure !== null) {
            [$failure, $this->failure] = [$this->failure, null];

            throw $failure;
        }

        if ($this->during !== null) {
            [$during, $this->during] = [$this->during, null];

            $during();
        }

        foreach ($this->links as [$connection, $linkIssuer, $linkSubject, $link]) {
            if ($connection === $connectionId && $linkIssuer === $issuer && $linkSubject === $subject) {
                return $link;
            }
        }

        return null;
    }
}
