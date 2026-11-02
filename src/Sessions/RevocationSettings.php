<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Whether each per-event revocation the application may turn off ends sessions:
 * a connection disabled or deleted, and an identity's link to a connection
 * removed (`authentication.revocation.*`, each `true` or `false`, on unless
 * set). A value that is not a boolean fails closed with an
 * `InvalidArgumentException` when the trigger is first called, and
 * `authentication:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RevocationSettings
{
    /** @var string Prefix of every revocation setting's key. */
    private const string PREFIX = 'authentication.revocation.';

    /** @var list<\SineMacula\Laravel\Authentication\Events\Enums\RevocationReason> The triggers the application may turn off, by the reason each records. */
    private const array TRIGGERS = [
        RevocationReason::CONNECTION_DISABLED,
        RevocationReason::CONNECTION_DELETED,
        RevocationReason::LINK_REMOVED,
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * Whether the trigger that records the reason ends sessions: its setting,
     * `true` unless set; a reason no setting turns off always does.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $trigger
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isEnabled(RevocationReason $trigger): bool
    {
        if (!in_array($trigger, self::TRIGGERS, true)) {
            return true;
        }

        $value = $this->config->get(self::PREFIX . $trigger->value, true);

        return is_bool($value) ? $value : throw new \InvalidArgumentException(sprintf('%s%s must be true or false.', self::PREFIX, $trigger->value));
    }

    /**
     * Read every setting, failing closed on the first that is malformed;
     * `authentication:check` runs it.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        foreach (self::TRIGGERS as $trigger) {
            $this->isEnabled($trigger);
        }
    }
}
