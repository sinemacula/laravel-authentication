<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

/**
 * The contributors that add keys to the authentication context, each under a
 * namespace of its own, in the order they were registered.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ContextContributors
{
    /** @var array<string, string> The contributors' abstracts, by namespace, in the order registered. */
    private array $contributors = [];

    /**
     * Register the contributor resolved from `$contributor` under the
     * namespace.
     *
     * @param  string  $namespace
     * @param  string  $contributor
     * @return void
     *
     * @throws \LogicException
     */
    public function register(string $namespace, string $contributor): void
    {
        if (!ContextKeys::isNamespace($namespace)) {
            $message = 'An authentication context contributor cannot be registered under [%s]: a namespace is a lower-case letter'
                . ' and then up to 31 lower-case letters, digits or underscores, and not the package\'s own [%s].';

            throw new \LogicException(sprintf($message, $namespace, AuthenticationContext::NAMESPACE));
        }

        if (array_key_exists($namespace, $this->contributors)) {
            throw new \LogicException(sprintf('An authentication context contributor is already registered under [%s]: %s.', $namespace, $this->contributors[$namespace]));
        }

        $this->contributors[$namespace] = $contributor;
    }

    /**
     * The contributors' abstracts, by namespace, in the order registered.
     *
     * @return array<string, string>
     */
    public function registered(): array
    {
        return $this->contributors;
    }
}
