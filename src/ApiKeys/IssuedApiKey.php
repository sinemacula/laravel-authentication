<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

/**
 * A key the service just issued: the one place its plaintext exists. Show it to
 * whoever asked for it once; only its digest is stored, so it cannot be shown
 * again. The key is held as a `\SensitiveParameterValue` and read through
 * `key()`, so no dump of the object (Laravel's VarDumper, `print_r`,
 * `var_export`) shows it, and serialising the object throws.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IssuedApiKey
{
    /** @var \SensitiveParameterValue The key a client presents, `<prefix>_<public>_<secret>`, shown once. */
    private \SensitiveParameterValue $key;

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

        // The key a client presents, held out of every dump.
        #[\SensitiveParameter]
        string $key,

        /** What may be shown about the key afterwards. */
        public ApiKeySummary $summary,
    ) {
        $this->key = new \SensitiveParameterValue($key);
    }

    /**
     * The key a client presents, `<prefix>_<public>_<secret>`: show it once.
     *
     * @return string
     */
    public function key(): string
    {
        return $this->key->getValue();
    }
}
