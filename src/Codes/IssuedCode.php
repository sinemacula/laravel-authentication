<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A one-time code, or a reset link's token, just issued: the secret in clear,
 * which exists only here and in the encrypted delivery job, the issuance it
 * belongs to, and when it expires.
 *
 * The secret is held as a private `Secret`, so no dump of the object, nor of a
 * trace that holds it, shows it. Unlike a `Secret` the issued code serialises,
 * because it travels inside the delivery job, whose payload is encrypted
 * (`ShouldBeEncrypted`): serialising writes the plaintext explicitly for that
 * payload, and nothing else serialises it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedCode
{
    /** @var \SineMacula\Laravel\Authentication\Secrets\Secret The code, or the token. */
    private Secret $code;

    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  string  $issueId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        // The code, or the token, in clear.
        #[\SensitiveParameter]
        string $code,

        /** Random identifier of this issuance, which a later issuance for the binding replaces. */
        public string $issueId,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,
    ) {
        $this->code = new Secret($code);
    }

    /**
     * The fields the encrypted delivery job's payload carries, the code in
     * clear among them.
     *
     * @return array{code: string, issue_id: string, expires_at: \Carbon\CarbonImmutable}
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        return ['code' => $this->code->reveal(), 'issue_id' => $this->issueId, 'expires_at' => $this->expiresAt];
    }

    /**
     * Restore the issued code from the delivery job's payload.
     *
     * @param  array{code: string, issue_id: string, expires_at: \Carbon\CarbonImmutable}  $data
     * @return void
     *
     * @throws \InvalidArgumentException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __unserialize(array $data): void
    {
        $this->code      = new Secret($data['code']);
        $this->issueId   = $data['issue_id'];
        $this->expiresAt = $data['expires_at'];
    }

    /**
     * What a dump shows: the issuance and its expiry, never the code.
     *
     * @return array{code: string, issueId: string, expiresAt: \Carbon\CarbonImmutable}
     */
    public function __debugInfo(): array
    {
        return ['code' => Secret::REDACTED, 'issueId' => $this->issueId, 'expiresAt' => $this->expiresAt];
    }

    /**
     * The code, or the token, in clear.
     *
     * @return string
     */
    public function code(): string
    {
        return $this->code->reveal();
    }

    /**
     * The code as the secret the delivery hands its sender.
     *
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     */
    public function secret(): Secret
    {
        return $this->code;
    }
}
