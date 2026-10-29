<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;

/**
 * Takes the sign counter check out of the WebAuthn library's assertion
 * ceremony: it accepts every counter, because the package applies its own rule
 * (`SignCounter`) after the ceremony, against the stored count, as one
 * compare-and-set on the passkey's row, which the library's in-memory check
 * cannot do.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeferredCounterCheck implements CounterChecker
{
    /**
     * Accept the counter; `SignCounter` judges it once the ceremony passed.
     *
     * @param  \Webauthn\CredentialRecord  $credentialRecord
     * @param  int  $currentCounter
     * @return void
     */
    #[\Override]
    public function check(CredentialRecord $credentialRecord, int $currentCounter): void {}
}
