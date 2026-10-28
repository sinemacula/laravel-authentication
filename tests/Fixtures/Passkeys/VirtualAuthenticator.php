<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys;

/**
 * A software authenticator and browser for the passkey tests: it answers the
 * creation and request options the package hands out with the JSON a browser's
 * `PublicKeyCredential.toJSON()` sends, signed with real ES256, EdDSA or RS256
 * keys it keeps for each credential it created, so the package verifies them
 * exactly as it would a hardware or platform authenticator's.
 *
 * Every flag and value an attack or a fault could change is a property the
 * tests set: the origin the browser reports, the relying party id hashed into
 * the authenticator data, the user presence and verification flags, the backup
 * bits, the attestation format, and how far each assertion moves the sign
 * counter (0 for an authenticator without one, such as a synced passkey).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VirtualAuthenticator
{
    /** @var int COSE identifier of ES256. */
    public const int ES256 = -7;

    /** @var int COSE identifier of EdDSA. */
    public const int EDDSA = -8;

    /** @var int COSE identifier of RS256. */
    public const int RS256 = -257;

    /** @var int Flag: the user was present. */
    private const int USER_PRESENT = 0x01;

    /** @var int Flag: the user was verified. */
    private const int USER_VERIFIED = 0x04;

    /** @var int Flag: the credential may be backed up. */
    private const int BACKUP_ELIGIBLE = 0x08;

    /** @var int Flag: the credential is backed up. */
    private const int BACKED_UP = 0x10;

    /** @var int Flag: attested credential data follows. */
    private const int ATTESTED = 0x40;

    /** @var ?string Origin the browser reports; `null` for the first origin the options' relying party would use. */
    public ?string $origin = null;

    /** @var ?string Relying party id hashed into the authenticator data; `null` for the one the options name. */
    public ?string $rpId = null;

    /** @var ?string Top-level origin of a frame the ceremony runs in; `null` for a top-level ceremony. */
    public ?string $topOrigin = null;

    /** @var bool Whether the browser reports the ceremony cross-origin without naming the top-level origin, as WebAuthn Level 2 browsers do. */
    public bool $crossOrigin = false;

    /** @var bool Whether the user is reported present. */
    public bool $userPresent = true;

    /** @var bool Whether the user is reported verified. */
    public bool $userVerified = true;

    /** @var bool Whether credentials report they may be backed up. */
    public bool $backupEligible = true;

    /** @var bool Whether credentials report they are backed up. */
    public bool $backedUp = true;

    /** @var int How far each assertion moves the sign counter; 0 for an authenticator without one. */
    public int $counterStep = 1;

    /** @var string Attestation statement format a created credential is returned with: `none` or `packed` (self attestation). */
    public string $format = 'none';

    /** @var string AAGUID a created credential reports, 16 bytes; all zeros for none. */
    public string $aaguid = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    /** @var list<string> Transports a created credential reports. */
    public array $transports = ['internal', 'hybrid'];

    /** @var array<string, array{key: \OpenSSLAsymmetricKey|string, alg: int, rp: string, user: string, counter: int}> Credentials created, keyed by their raw id. */
    private array $credentials = [];

    /**
     * Constructor.
     *
     * @param  string  $defaultOrigin
     * @param  int  $algorithm
     */
    public function __construct(

        /** Origin the browser reports when no other is set. */
        private readonly string $defaultOrigin = 'https://app.example.test',

        /** COSE algorithm of the keys it creates. */
        public int $algorithm = self::ES256,
    ) {}

    /**
     * Create a credential for the creation options (with the raw id given, or a
     * random one of the length) and return the browser's registration response.
     *
     * @param  array<string, mixed>  $options
     * @param  int  $idLength
     * @param  ?string  $id
     * @return array<string, mixed>
     *
     * @throws \Random\RandomException
     * @throws \SodiumException
     */
    public function create(array $options, int $idLength = 32, ?string $id = null): array
    {
        $rp   = $options['rp'];
        $user = $options['user'];

        assert(is_array($rp) && is_string($rp['id']) && is_array($user) && is_string($user['id']));

        $id ??= random_bytes($idLength);
        [$key, $cose] = $this->keyPair($this->algorithm);

        $this->credentials[$id] = ['key' => $key, 'alg' => $this->algorithm, 'rp' => $rp['id'], 'user' => self::decode($user['id']), 'counter' => 0];

        $clientData = $this->clientData('webauthn.create', $options);
        $authData   = $this->authenticatorData($rp['id'], self::ATTESTED, 0)
            . $this->aaguid . pack('n', strlen($id)) . $id . $cose;

        $statement = $this->format === 'packed'
            ? [[Cbor::text('alg'), $this->algorithm], [Cbor::text('sig'), $this->sign($id, $authData . hash('sha256', $clientData, true))]]
            : [];

        $attestation = Cbor::encode([
            [Cbor::text('fmt'), Cbor::text($this->format)],
            [Cbor::text('attStmt'), $statement],
            [Cbor::text('authData'), $authData],
        ]);

        return [
            'id'       => self::encode($id),
            'rawId'    => self::encode($id),
            'type'     => 'public-key',
            'response' => [
                'clientDataJSON'    => self::encode($clientData),
                'attestationObject' => self::encode($attestation),
                'transports'        => $this->transports,
            ],
            'clientExtensionResults'  => [],
            'authenticatorAttachment' => 'platform',
        ];
    }

    /**
     * Sign an assertion for the request options with the credential (by default
     * the one created last for the options' relying party) and return the
     * browser's authentication response.
     *
     * @param  array<string, mixed>  $options
     * @param  ?string  $credentialId
     * @return array<string, mixed>
     *
     * @throws \SodiumException
     */
    public function get(array $options, ?string $credentialId = null): array
    {
        $id = $credentialId === null ? $this->lastFor($options) : self::decode($credentialId);

        $credential = $this->credentials[$id];

        $credential['counter'] += $this->counterStep;

        $this->credentials[$id] = $credential;
        $clientData             = $this->clientData('webauthn.get', $options);
        $authData               = $this->authenticatorData($credential['rp'], 0, $credential['counter']);

        return [
            'id'       => self::encode($id),
            'rawId'    => self::encode($id),
            'type'     => 'public-key',
            'response' => [
                'clientDataJSON'    => self::encode($clientData),
                'authenticatorData' => self::encode($authData),
                'signature'         => self::encode($this->sign($id, $authData . hash('sha256', $clientData, true))),
                'userHandle'        => self::encode($credential['user']),
            ],
            'clientExtensionResults'  => [],
            'authenticatorAttachment' => 'platform',
        ];
    }

    /**
     * The id of the credential created last, base64url-encoded.
     *
     * @return string
     */
    public function lastCredentialId(): string
    {
        $ids = array_keys($this->credentials);

        return self::encode((string) end($ids));
    }

    /**
     * Set the sign counter of a credential, as a clone of it might hold.
     *
     * @param  string  $credentialId
     * @param  int  $counter
     * @return void
     */
    public function setCounter(string $credentialId, int $counter): void
    {
        $credential = $this->credentials[self::decode($credentialId)];

        $credential['counter'] = $counter;

        $this->credentials[self::decode($credentialId)] = $credential;
    }

    /**
     * Encode bytes as unpadded base64url.
     *
     * @param  string  $bytes
     * @return string
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode unpadded base64url.
     *
     * @param  string  $encoded
     * @return string
     */
    public static function decode(string $encoded): string
    {
        return (string) base64_decode(strtr($encoded, '-_', '+/'), true);
    }

    /**
     * The string at the path in options or a response.
     *
     * @param  array<array-key, mixed>  $value
     * @param  string  ...$path
     * @return string
     *
     * @throws \LogicException
     */
    public static function at(array $value, string ...$path): string
    {
        $found = $value;

        foreach ($path as $key) {
            $found = is_array($found) ? $found[$key] ?? null : null;
        }

        return is_string($found) ? $found : throw new \LogicException('No string at ' . implode('.', $path) . '.');
    }

    /**
     * The id of the credential created last for the options' relying party.
     *
     * @param  array<string, mixed>  $options
     * @return string
     *
     * @throws \LogicException
     */
    private function lastFor(array $options): string
    {
        $rp = $options['rpId'] ?? null;

        foreach (array_reverse($this->credentials, true) as $id => $credential) {
            if ($credential['rp'] === $rp) {
                return $id;
            }
        }

        throw new \LogicException('The authenticator holds no credential for the relying party.');
    }

    /**
     * The client data the browser builds for the ceremony.
     *
     * @param  string  $type
     * @param  array<string, mixed>  $options
     * @return string
     */
    private function clientData(string $type, array $options): string
    {
        $data = [
            'type'        => $type,
            'challenge'   => $options['challenge'],
            'origin'      => $this->origin ?? $this->defaultOrigin,
            'crossOrigin' => $this->crossOrigin || $this->topOrigin !== null,
        ];

        return (string) json_encode($this->topOrigin === null ? $data : [...$data, 'topOrigin' => $this->topOrigin], JSON_UNESCAPED_SLASHES);
    }

    /**
     * The authenticator data: the relying party id's hash, the flags and the
     * sign counter.
     *
     * @param  string  $rp
     * @param  int  $flags
     * @param  int  $counter
     * @return string
     */
    private function authenticatorData(string $rp, int $flags, int $counter): string
    {
        $flags |= ($this->userPresent ? self::USER_PRESENT : 0)
            | ($this->userVerified ? self::USER_VERIFIED : 0)
            | ($this->backupEligible ? self::BACKUP_ELIGIBLE : 0)
            | ($this->backedUp ? self::BACKED_UP : 0);

        return hash('sha256', $this->rpId ?? $rp, true) . chr($flags) . pack('N', $counter);
    }

    /**
     * Sign the data with the credential's private key, in the form WebAuthn
     * carries a signature of its algorithm.
     *
     * @param  string  $id
     * @param  string  $data
     * @return string
     *
     * @throws \SodiumException
     */
    private function sign(string $id, string $data): string
    {
        $credential = $this->credentials[$id];

        if ($credential['alg'] === self::EDDSA) {
            assert(is_string($credential['key']));

            return sodium_crypto_sign_detached($data, $credential['key']);
        }

        assert($credential['key'] instanceof \OpenSSLAsymmetricKey);

        openssl_sign($data, $signature, $credential['key'], OPENSSL_ALGO_SHA256);

        return $signature;
    }

    /**
     * A new key pair of the algorithm: the private key and the COSE public key.
     *
     * @param  int  $algorithm
     * @return array{0: \OpenSSLAsymmetricKey|string, 1: string}
     *
     * @throws \SodiumException
     */
    private function keyPair(int $algorithm): array
    {
        if ($algorithm === self::EDDSA) {

            $pair = sodium_crypto_sign_keypair();

            return [sodium_crypto_sign_secretkey($pair), Cbor::encode([[1, 1], [3, self::EDDSA], [-1, 6], [-2, sodium_crypto_sign_publickey($pair)]])];
        }

        if ($algorithm === self::RS256) {

            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

            assert($key instanceof \OpenSSLAsymmetricKey);

            $rsa = openssl_pkey_get_details($key)['rsa'] ?? [];

            return [$key, Cbor::encode([[1, 3], [3, self::RS256], [-1, $rsa['n']], [-2, $rsa['e']]])];
        }

        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        assert($key instanceof \OpenSSLAsymmetricKey);

        $ec = openssl_pkey_get_details($key)['ec'] ?? [];

        return [$key, Cbor::encode([[1, 2], [3, self::ES256], [-1, 1], [-2, str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)], [-3, str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)]])];
    }
}
