<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;

/**
 * Accepts every sign counter in the WebAuthn library's ceremony, leaving the
 * check to `SignCounter`'s compare-and-set on the stored count.
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
