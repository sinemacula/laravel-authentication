<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\Passkey;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Stores, finds, updates and removes passkeys, each scoped to the relying party
 * it was registered for: a guard only ever sees the passkeys of its own relying
 * party id.
 *
 * A credential is found by the SHA-256 digest of its raw id, since an id can be
 * longer than an index can hold. Every read is from the write connection, and
 * every write is one conditional statement: a registration inserts unless the
 * credential is already registered, a use moves the sign counter only from the
 * count it was verified against, and a removal deletes only the owner's
 * passkey.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PasskeyCredentials
{
    /** @var string The AAGUID of an authenticator that reports none. */
    private const string NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    /** @var list<string> Columns a verified use writes. */
    private const array USE_COLUMNS = ['sign_count', 'backup_state', 'uv_initialized', 'last_used_at', 'updated_at'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The passkey of the relying party with the raw credential id, if any, the
     * relying party matched exactly, whatever the column's collation.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  string  $credentialId
     * @return ?\SineMacula\Laravel\Authentication\Models\Passkey
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function find(RelyingParty $rp, #[\SensitiveParameter] string $credentialId): ?Passkey
    {
        $passkey = WriteConnection::query((new Passkey)->newQuery())
            ->where('credential_id_hash', self::digest($credentialId))
            ->where('rp_id', $rp->id)
            ->first();

        return $passkey instanceof Passkey && $passkey->rp_id === $rp->id ? $passkey : null;
    }

    /**
     * The owner's passkeys for the relying party, oldest first. Each is checked
     * against the owner and the relying party exactly, since the columns'
     * collation may count distinct values, such as `alice` and `Alice`, as
     * equal.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @return list<\SineMacula\Laravel\Authentication\Models\Passkey>
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function of(RelyingParty $rp, Identity&Model $owner): array
    {
        [$type, $id] = PasskeyOwner::columns($owner);

        /** @var list<\SineMacula\Laravel\Authentication\Models\Passkey> */
        return WriteConnection::query((new Passkey)->newQuery())
            ->where('authenticatable_type', $type)
            ->where('authenticatable_id', $id)
            ->where('rp_id', $rp->id)
            ->orderBy('created_at')
            ->orderBy('id')
            ->get()
            ->filter(static fn (Passkey $passkey): bool => $passkey->rp_id === $rp->id && PasskeyOwner::owns($owner, $passkey))
            ->values()
            ->all();
    }

    /**
     * Store the credential a registration verified for the owner, unless it is
     * already registered (for anyone, under any relying party), and return the
     * stored passkey, or `null` when it was already registered.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \Webauthn\CredentialRecord  $record
     * @param  ?string  $name
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Models\Passkey
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function register(RelyingParty $rp, Identity&Model $owner, CredentialRecord $record, ?string $name, CarbonImmutable $now): ?Passkey
    {
        [$type, $id] = PasskeyOwner::columns($owner);

        $passkey = new Passkey;

        $passkey->forceFill([
            'id'                   => Str::uuid7()->toString(),
            'credential_id_hash'   => self::digest($record->publicKeyCredentialId),
            'credential_id'        => self::encode($record->publicKeyCredentialId),
            'authenticatable_type' => $type,
            'authenticatable_id'   => $id,
            'rp_id'                => $rp->id,
            'user_handle'          => self::encode($record->userHandle),
            'public_key'           => self::encode($record->credentialPublicKey),
            'sign_count'           => $record->counter,
            'transports'           => self::transports($record->transports),
            'aaguid'               => self::aaguid($record),
            'backup_eligible'      => $record->backupEligible === true,
            'backup_state'         => $record->backupStatus   === true,
            'uv_initialized'       => $record->uvInitialized  === true,
            'name'                 => $name,
            'created_at'           => $now,
            'updated_at'           => $now,
        ]);

        $inserted = $passkey->newQueryWithoutScopes()->toBase()->insertOrIgnore($passkey->getAttributes());

        if ($inserted !== 1) {
            return null;
        }

        $passkey->exists = true;

        return $passkey->syncOriginal();
    }

    /**
     * Record a verified use of the passkey: its new sign count, backup state
     * and last use, only while it still holds the count it was verified
     * against. Returns whether this call recorded it; when another use moved
     * the count first, or the passkey was removed meanwhile, it did not.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  \Webauthn\CredentialRecord  $verified
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    public static function use(Passkey $passkey, CredentialRecord $verified, CarbonImmutable $now): bool
    {
        $used = (clone $passkey)->forceFill([
            'sign_count'     => $verified->counter,
            'backup_state'   => $verified->backupStatus  === true,
            'uv_initialized' => $verified->uvInitialized === true,
            'last_used_at'   => $now,
            'updated_at'     => $now,
        ]);

        $updated = $passkey->newQueryWithoutScopes()
            ->toBase()
            ->where($passkey->getKeyName(), $passkey->getKey())
            ->where('sign_count', $passkey->sign_count)
            ->update(array_intersect_key($used->getAttributes(), array_flip(self::USE_COLUMNS)));

        if ($updated !== 1 && !self::matchedUnchanged($passkey, $verified)) {
            return false;
        }

        $passkey->setRawAttributes($used->getAttributes(), true);

        return true;
    }

    /**
     * Remove the owner's passkey of the relying party with the id, once it is
     * read and checked against the owner and the relying party exactly. Returns
     * whether this call removed it; an id that is not a UUID removes nothing,
     * without a query.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  string  $id
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @imperative
     */
    public static function remove(RelyingParty $rp, Identity&Model $owner, string $id): bool
    {
        if (!Str::isUuid($id)) {
            return false;
        }

        [$type, $key] = PasskeyOwner::columns($owner);

        $passkey = WriteConnection::query((new Passkey)->newQuery())
            ->whereKey($id)
            ->where('authenticatable_type', $type)
            ->where('authenticatable_id', $key)
            ->where('rp_id', $rp->id)
            ->first();

        return $passkey instanceof Passkey
            && $passkey->rp_id === $rp->id
            && PasskeyOwner::owns($owner, $passkey)
            && $passkey->newQueryWithoutScopes()->toBase()->where($passkey->getKeyName(), $id)->delete() === 1;
    }

    /**
     * The passkey as the library's credential record, to verify an assertion
     * against.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @return \Webauthn\CredentialRecord
     */
    public static function record(Passkey $passkey): CredentialRecord
    {
        return CredentialRecord::create(
            self::decode($passkey->credential_id),
            WebAuthn::PUBLIC_KEY,
            $passkey->transports,
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromString($passkey->aaguid ?? self::NIL_AAGUID),
            self::decode($passkey->public_key),
            self::userHandle($passkey),
            $passkey->sign_count,
            backupEligible: $passkey->backup_eligible,
            backupStatus: $passkey->backup_state,
            uvInitialized: $passkey->uv_initialized,
        );
    }

    /**
     * The raw user handle the passkey was registered under.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @return string
     */
    public static function userHandle(Passkey $passkey): string
    {
        return self::decode($passkey->user_handle);
    }

    /**
     * The passkey as a credential descriptor: its raw id and its transports.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @return array{0: string, 1: list<string>}
     */
    public static function descriptor(Passkey $passkey): array
    {
        return [self::decode($passkey->credential_id), $passkey->transports];
    }

    /**
     * Whether an update of a use that reported no row matched one all the same.
     * A count of 0 against a stored 0 moves nothing, so there is no race to
     * lose, but MySQL reports a row the update matched without changing it (a
     * second use within the same second) as unaffected. The passkey must still
     * hold 0 on the writer: one removed meanwhile is not used.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  \Webauthn\CredentialRecord  $verified
     * @return bool
     */
    private static function matchedUnchanged(Passkey $passkey, CredentialRecord $verified): bool
    {
        return $verified->counter === 0
            && WriteConnection::query($passkey->newQueryWithoutScopes())->whereKey($passkey->getKey())->where('sign_count', 0)->exists();
    }

    /**
     * The transports a response reported that WebAuthn defines, in order and
     * without repeats; others are not kept.
     *
     * @param  array<array-key, mixed>  $transports
     * @return list<string>
     */
    private static function transports(array $transports): array
    {
        return array_values(array_unique(array_filter(
            $transports,
            static fn (mixed $transport): bool => in_array($transport, PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORTS, true),
        )));
    }

    /**
     * The AAGUID of the credential's authenticator, or `null` for the nil one
     * an authenticator reports when it names none.
     *
     * @param  \Webauthn\CredentialRecord  $record
     * @return ?string
     */
    private static function aaguid(CredentialRecord $record): ?string
    {
        $aaguid = $record->aaguid->toRfc4122();

        return $aaguid === self::NIL_AAGUID ? null : $aaguid;
    }

    /**
     * The SHA-256 hex digest of a raw credential id, which the passkey is found
     * by.
     *
     * @param  string  $credentialId
     * @return string
     */
    private static function digest(#[\SensitiveParameter] string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    /**
     * Encode bytes as unpadded base64url.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode unpadded base64url the package stored.
     *
     * @param  string  $encoded
     * @return string
     */
    private static function decode(string $encoded): string
    {
        return (string) base64_decode(strtr($encoded, '-_', '+/'), true);
    }
}
