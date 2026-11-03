<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

/**
 * The contributors that add keys to the authentication context, each under a
 * namespace of its own, in the order they were registered. Register one in a
 * service provider's `boot()`:
 *
 * ```php
 * $this->app->make(ContextContributors::class)->register('sso', SsoContextContributor::class);
 * ```
 *
 * Each is a container abstract that resolves to an
 * `AuthenticationContextContributor`, resolved each time a context is built
 * from the container serving then (the request's own under Octane), so it may
 * depend on request-scoped services. A namespace is taken once: a second
 * registration under it, a registration under the package's own
 * (`authentication`) and a malformed one all fail loudly, so no contributor's
 * keys can overwrite another's. `mfa` and `sso` are kept for the further-factor
 * and single sign-on packages' adapters, which register them; the package
 * registers none itself.
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
     * namespace: a lower-case letter and then up to 31 lower-case letters,
     * digits or underscores, not `authentication`, and not one registered
     * already.
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
