<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;

/**
 * The standard Laravel `Attempting`, `Validated` and `Failed` event helpers,
 * with password-like credential keys removed.
 *
 * The caller's flow holds the single timebox; do not nest another here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property \SineMacula\Laravel\Authentication\Runtime\GuardContext $context
 */
trait ValidatesGuardCredentials
{
    /** @var string Credential key fragment that is always redacted from events. */
    protected const string REDACTED_CREDENTIAL_FRAGMENT = 'password';

    /**
     * Fire the standard Laravel `Validated` event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function fireValidatedEvent(Authenticatable $user): void
    {
        $this->context->dispatch(new Validated($this->context->name(), $user));
    }

    /**
     * Fire the standard Laravel `Attempting` event with the credentials
     * redacted.
     *
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    protected function fireAttemptingEvent(#[\SensitiveParameter] array $credentials): void
    {
        $this->context->dispatch(new Attempting($this->context->name(), $this->redactCredentials($credentials), false));
    }

    /**
     * Fire the standard Laravel `Failed` event with the credentials redacted.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    protected function fireFailedEvent(?Authenticatable $user, #[\SensitiveParameter] array $credentials): void
    {
        $this->context->dispatch(new Failed($this->context->name(), $user, $this->redactCredentials($credentials)));
    }

    /**
     * Return the credentials without their password-like keys, for the events
     * any listener, queued job or log can capture.
     *
     * @param  array<string, mixed>  $credentials
     * @return array<string, mixed>
     */
    protected function redactCredentials(#[\SensitiveParameter] array $credentials): array
    {
        $fragments = $this->redactedCredentialFragments();

        return array_filter(
            $credentials,
            static function (int|string $key) use ($fragments): bool {

                $name = strtolower((string) $key);

                foreach ($fragments as $fragment) {
                    if (str_contains($name, $fragment)) {
                        return false;
                    }
                }

                return true;
            },
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * Resolve the lower-cased key fragments to redact.
     *
     * @return list<string>
     */
    private function redactedCredentialFragments(): array
    {
        $fragments = [self::REDACTED_CREDENTIAL_FRAGMENT];

        foreach (Config::array('authentication.events.redacted_credential_keys', []) as $fragment) {

            if (!is_string($fragment) || $fragment === '') {
                continue;
            }

            $fragments[] = strtolower($fragment);
        }

        return $fragments;
    }
}
