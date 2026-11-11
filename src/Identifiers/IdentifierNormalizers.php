<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Identifiers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

/**
 * The identifier normalisers by type, read from
 * `authentication.identifiers.normalizers` on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierNormalizers
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
        return array_key_exists($type, $this->normalizers());
    }

    /**
     * The normaliser registered for the identifier type.
     *
     * @param  string  $type
     * @return \SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $type): IdentifierNormalizer
    {
        $abstract = $this->normalizers()[$type]
            ?? throw new \InvalidArgumentException("No identifier normaliser is registered for [{$type}]: add it to `authentication.identifiers.normalizers`.");

        $normalizer = $this->container->make($abstract);

        if (!$normalizer instanceof IdentifierNormalizer) {

            $message = "The identifier normaliser for [{$type}], [{$abstract}], resolved to ["
                . get_debug_type($normalizer) . '] instead of [' . IdentifierNormalizer::class . '].';

            throw new \InvalidArgumentException($message);
        }

        return $normalizer;
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
        return array_keys($this->normalizers());
    }

    /**
     * The configured map of identifier types to normaliser abstracts.
     *
     * @return array<string, non-empty-string>
     *
     * @throws \InvalidArgumentException
     */
    private function normalizers(): array
    {
        $map = $this->config->get('authentication.identifiers.normalizers');

        if (!is_array($map)) {
            throw new \InvalidArgumentException('`authentication.identifiers.normalizers` must be an array of identifier types to normaliser classes.');
        }

        foreach ($map as $type => $abstract) {
            if (!is_string($type) || !IdentifierType::isValid($type) || !is_string($abstract) || $abstract === '') {
                $message = '`authentication.identifiers.normalizers` must map identifier types'
                    . ' (lower-case letters, digits and underscores) to normaliser classes.';

                throw new \InvalidArgumentException($message);
            }
        }

        /** @var array<string, non-empty-string> $map */
        return $map;
    }
}
