<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;

/**
 * A model provider that looks an `email` credential up in the model's
 * `email_address` column, as an application whose column is named otherwise
 * would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MappedColumnModelProvider extends ModelProvider
{
    /**
     * Find the identity by its `email_address` for an `email` credential.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        if (array_key_exists('email', $credentials)) {
            $credentials['email_address'] = $credentials['email'];

            unset($credentials['email']);
        }

        return parent::retrieveByCredentials($credentials);
    }
}
