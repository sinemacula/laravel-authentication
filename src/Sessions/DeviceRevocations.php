<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;

/**
 * Revokes devices for the session service: one device, or every device of one
 * or more scopes (an identity's, or a principal's).
 *
 * Each device is revoked by its own conditional `UPDATE` (only while it is not
 * revoked yet), so revoking is idempotent, the first revocation's time and
 * reason are kept, and of two calls racing for a device only the one that
 * changed the row reports it. Reports run once the revocation commits on the
 * device's own connection, never for one rolled back.
 *
 * A bulk revocation first moves each scope's "tokens valid after" cutoff to
 * `$now` on the scope's own connection, then, in one transaction on the device
 * model's connection (which also holds the pending sign-ins), revokes every
 * unrevoked device of each scope, read on the write connection in key order in
 * chunks of 500, deletes the scope's pending sign-ins, so a further factor or a
 * principal choice issued before cannot start a session afterwards, and deletes
 * the pending identifier changes of an identity's scope (also kept on that
 * connection), so a change link requested from a session that ends, which needs
 * no session to confirm, cannot move the account afterwards. A failure in the
 * transaction leaves the cutoffs moved: more is cut off, never less, and a
 * retry is idempotent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeviceRevocations
{
    /** @var int Devices read per chunk of a bulk revocation. */
    public const int CHUNK = 500;

    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore The conditional revocation write. */
    private RefreshRotationStore $store;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers the reports until the revocations commit. */
    private AfterCommit $afterCommit;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(ConnectionResolverInterface $connections, \Closure $transactions)
    {
        $this->store       = new RefreshRotationStore($connections);
        $this->afterCommit = new AfterCommit($transactions);
    }

    /**
     * Revoke the device unless it is already revoked, and run the report once
     * the revocation commits. Returns whether this call revoked it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(): void  $report
     * @return bool
     *
     * @imperative
     */
    public function revoke(EloquentDevice&Model $device, RevocationReason $reason, CarbonImmutable $now, \Closure $report): bool
    {
        $revoked = $this->store->revoke($device, $reason, $now);

        if ($revoked) {
            $this->afterCommit->run($device, $report);
        }

        return $revoked;
    }

    /**
     * End every session of the scopes, except on the given device, and return
     * how many devices this call revoked. Once the transaction commits, each
     * revoked device is reported, then each scope with its count and the cutoff
     * this call set for it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice, \SineMacula\Laravel\Authentication\Sessions\RevocationScope): void  $deviceRevoked
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\RevocationScope, int, ?\Carbon\CarbonImmutable): void  $scopeEnded
     * @return int
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    public function revokeScopes(array $scopes, RevocationReason $reason, ?Device $except, CarbonImmutable $now, \Closure $deviceRevoked, \Closure $scopeEnded): int
    {
        $cutoffs = array_map(static fn (RevocationScope $scope): ?CarbonImmutable => $scope->cutoff?->invalidateTokensIssuedBefore($now) === true ? $now : null, $scopes);
        $anchor  = DeviceLookup::model();

        return $anchor->getConnection()->transaction(function () use ($scopes, $cutoffs, $reason, $except, $now, $deviceRevoked, $scopeEnded, $anchor): int {

            $total = 0;

            foreach ($scopes as $index => $scope) {

                $revoked = $this->revokeDevicesOf($scope, $reason, $except, $now, $deviceRevoked);

                self::deletePendings($scope);
                self::forgetChanges($scope);

                $cutoff = $cutoffs[$index];

                $this->afterCommit->run($anchor, static function () use ($scopeEnded, $scope, $revoked, $cutoff): void {
                    $scopeEnded($scope, $revoked, $cutoff);
                });

                $total += $revoked;
            }

            return $total;
        });
    }

    /**
     * Revoke every unrevoked device of the scope but the excepted one, reading
     * them on the write connection in key order, a chunk at a time, and queue
     * each revoked device's report.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationScope  $scope
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice, \SineMacula\Laravel\Authentication\Sessions\RevocationScope): void  $deviceRevoked
     * @return int
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function revokeDevicesOf(RevocationScope $scope, RevocationReason $reason, ?Device $except, CarbonImmutable $now, \Closure $deviceRevoked): int
    {
        if ($scope->devices === null) {
            return 0;
        }

        [$query, $model] = $scope->devices;

        $query->whereNull($model->qualifyColumn($model->getRevokedAtName()));

        if ($except instanceof $model) {
            $query->whereKeyNot($except->getDeviceIdentifier());
        }

        return WriteConnection::during($model, function () use ($query, $reason, $now, $deviceRevoked, $scope): int {

            $revoked = 0;

            /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice $device */
            foreach ($query->lazyById(self::CHUNK) as $device) {

                if (!$this->revoke($device, $reason, $now, static fn () => $deviceRevoked($device, $scope))) {
                    continue;
                }

                $revoked++;
            }

            return $revoked;
        });
    }

    /**
     * Delete the scope's pending sign-ins, whatever their purpose.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationScope  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private static function deletePendings(RevocationScope $scope): void
    {
        if ($scope->pendings === null) {
            return;
        }

        (new PendingSignIn)->newQueryWithoutScopes()->toBase()->where($scope->pendings)->delete();
    }

    /**
     * Delete the scope's pending identifier changes, whatever guard requested
     * them, in one statement.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationScope  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private static function forgetChanges(RevocationScope $scope): void
    {
        if ($scope->changes === []) {
            return;
        }

        PendingChanges::forget($scope->changes);
    }
}
