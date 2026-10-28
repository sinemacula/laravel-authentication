<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

/**
 * A key the service just issued: the one place its plaintext exists. Show it to
 * whoever asked for it once; only its digest is stored, so it cannot be shown
 * again. Dumped, it shows the key redacted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IssuedApiKey
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary  $summary
     */
    public function __construct(

        /** The key's id. */
        public string $id,

        /** The key a client presents, `<prefix>_<public>_<secret>`, shown once. */
        #[\SensitiveParameter]
        public string $key,

        /** What may be shown about the key afterwards. */
        public ApiKeySummary $summary,
    ) {}

    /**
     * The key's parts for a dump, the key itself redacted.
     *
     * @return array{id: string, key: string, summary: \SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary}
     */
    public function __debugInfo(): array
    {
        return ['id' => $this->id, 'key' => '[redacted]', 'summary' => $this->summary];
    }
}
