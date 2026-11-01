<?php

declare(strict_types = 1);

namespace Tests\Feature\ApiKeys;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of admitting a live key's owner as the principal it was issued
 * for, once the key's binding holds: `ApplicationAccess` decides whether that
 * principal may use the application the key authenticates for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyAdmission::class)]
final class ApiKeyAdmissionTest extends TestCase
{
    /** @var string Guard the key authenticates for. */
    private const string GUARD = 'machines';

    /**
     * A key whose owner and principal still hold, and whose principal the
     * application access lets use the guard, admits them, in no tenant; the
     * access is asked about that principal for that guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyWhosePrincipalMayUseTheApplicationIsAdmitted(): void
    {
        $client = self::client();
        $asked  = [];

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static function (string $application, Principal $principal) use (&$asked): bool {
            $asked[] = [$application, $principal];

            return false;
        }));

        $admitted = self::admission($client)->admit(self::keyOf($client));

        self::assertInstanceOf(Admitted::class, $admitted);
        self::assertSame($client, $admitted->identity);
        self::assertSame($client, $admitted->principal);
        self::assertNull($admitted->tenant);
        self::assertSame([[self::GUARD, $client]], $asked);
    }

    /**
     * A key whose principal the application access keeps out is refused as
     * `principal_ineligible`, with the owner and principal it established.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyWhosePrincipalTheApplicationAccessRefusesIsIneligible(): void
    {
        $client = self::client();

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => true));

        $refused = self::admission($client)->admit(self::keyOf($client));

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refused->reason);
        self::assertSame($client, $refused->identity);
        self::assertSame($client, $refused->principal);
        self::assertNull($refused->tenant);
    }

    /**
     * A key whose binding no longer holds (here it records a tenant the
     * principal is not in) is refused as `principal_mismatch` before the
     * application access is asked, so a refusing access never hides it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyWhoseBindingNoLongerHoldsIsAMismatchBeforeTheAccessIsAsked(): void
    {
        $client = self::client();
        $asked  = 0;

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static function () use (&$asked): bool {
            $asked++;

            return true;
        }));

        $refused = self::admission($client)->admit(self::keyOf($client)->forceFill(['tenant_type' => 'tenants', 'tenant_id' => '9']));

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $refused->reason);
        self::assertSame($client, $refused->principal);
        self::assertSame(0, $asked);
    }

    /**
     * An active machine client that is its own principal, unsaved, with a key.
     *
     * @return \Tests\Integration\Fixtures\MachineClient
     */
    private static function client(): MachineClient
    {
        return (new MachineClient)->forceFill(['id' => 7, 'is_active' => true]);
    }

    /**
     * The admission of the guard, whose provider reloads the client and whose
     * resolver resolves it as its own principal.
     *
     * @param  \Tests\Integration\Fixtures\MachineClient  $client
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAdmission
     */
    private static function admission(MachineClient $client): ApiKeyAdmission
    {
        $provider = \Mockery::mock(IdentityProvider::class);
        $resolver = \Mockery::mock(PrincipalResolver::class);

        $provider->shouldReceive('retrieveById')->with('7')->andReturn($client);
        $resolver->shouldReceive('resolve')->with($client, '7')->andReturn($client);

        return new ApiKeyAdmission(self::GUARD, $provider, $resolver);
    }

    /**
     * A key issued to the client, as itself, in no tenant.
     *
     * @param  \Tests\Integration\Fixtures\MachineClient  $client
     * @return \SineMacula\Laravel\Authentication\Models\ApiKey
     */
    private static function keyOf(MachineClient $client): ApiKey
    {
        return (new ApiKey)->forceFill([
            'authenticatable_type' => $client->getMorphClass(),
            'authenticatable_id'   => '7',
            'principal_type'       => $client->getMorphClass(),
            'principal_id'         => '7',
            'tenant_type'          => null,
            'tenant_id'            => null,
        ]);
    }
}
