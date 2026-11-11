<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A key the service just issued, the one place its plaintext exists; show it
 * once, as only its digest is stored.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IssuedApiKey
{
    /** @var \SineMacula\Laravel\Authentication\Secrets\Secret The key a client presents, `<prefix>_<public>_<secret>`, shown once. */
    private Secret $key;

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary  $summary
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The key's id. */
        public string $id,

        // The key a client presents.
        #[\SensitiveParameter]
        string $key,

        /** What may be shown about the key afterwards. */
        public ApiKeySummary $summary,
    ) {
        $this->key = new Secret($key);
    }

    /**
     * The key a client presents, to reveal once into the response that shows
     * it.
     *
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     */
    public function key(): Secret
    {
        return $this->key;
    }
}
