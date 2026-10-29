<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Identifiers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser;

/**
 * The identifier normalisers, by identifier type, from
 * `authentication.identifiers.normalisers`: a map of type names to container
 * abstracts that resolve to an `IdentifierNormaliser`.
 *
 * The map is read on every call, and an entry whose name is not a valid
 * identifier type, whose abstract is not a non-empty string, or that does not
 * resolve to a normaliser fails closed with an `InvalidArgumentException`
 * rather than leaving identifiers of that type as given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierNormalisers
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Config\Repository  $config
     */
    public function __construct(

        /** Container the normalisers are resolved from. */
        private Container $container,

        /** Configuration holding the normaliser map. */
        private ConfigRepository $config,
    ) {}

    /**
     * Whether a normaliser is registered for the identifier type.
     *
     * @param  string  $type
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function has(string $type): bool
    {
        return array_key_exists($type, $this->normalisers());
    }

    /**
     * The normaliser registered for the identifier type.
     *
     * @param  string  $type
     * @return \SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $type): IdentifierNormaliser
    {
        $abstract = $this->normalisers()[$type]
            ?? throw new \InvalidArgumentException("No identifier normaliser is registered for [{$type}]: add it to `authentication.identifiers.normalisers`.");

        $normaliser = $this->container->make($abstract);

        if (!$normaliser instanceof IdentifierNormaliser) {

            $message = "The identifier normaliser for [{$type}], [{$abstract}], resolved to ["
                . get_debug_type($normaliser) . '] instead of [' . IdentifierNormaliser::class . '].';

            throw new \InvalidArgumentException($message);
        }

        return $normaliser;
    }

    /**
     * The identifier types a normaliser is registered for, in their configured
     * order.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function types(): array
    {
        return array_keys($this->normalisers());
    }

    /**
     * The configured map of identifier types to normaliser abstracts.
     *
     * @return array<string, non-empty-string>
     *
     * @throws \InvalidArgumentException
     */
    private function normalisers(): array
    {
        $map = $this->config->get('authentication.identifiers.normalisers');

        if (!is_array($map)) {
            throw new \InvalidArgumentException('`authentication.identifiers.normalisers` must be an array of identifier types to normaliser classes.');
        }

        foreach ($map as $type => $abstract) {
            if (!is_string($type) || !IdentifierType::isValid($type) || !is_string($abstract) || $abstract === '') {
                $message = '`authentication.identifiers.normalisers` must map identifier types'
                    . ' (lower-case letters, digits and underscores) to normaliser classes.';

                throw new \InvalidArgumentException($message);
            }
        }

        /** @var array<string, non-empty-string> $map */
        return $map;
    }
}
