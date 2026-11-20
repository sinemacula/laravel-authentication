<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use Tests\TestCase;

/**
 * Feature tests for where the proof and provenance models keep their rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProof::class)]
#[CoversClass(SessionProvenance::class)]
final class SessionProofTest extends TestCase
{
    /**
     * Each model uses its configured table, and the shipped name when none is
     * configured.
     *
     * @return void
     */
    public function testTheTablesAreTheConfiguredOnes(): void
    {
        Config::set('authentication.proofs.table', 'auth_proofs');
        Config::set('authentication.proofs.provenance_table', 'auth_provenance');

        self::assertSame('auth_proofs', (new SessionProof)->getTable());
        self::assertSame('auth_provenance', (new SessionProvenance)->getTable());

        Config::set('authentication.proofs', []);

        self::assertSame('authentication_proofs', (new SessionProof)->getTable());
        self::assertSame('authentication_provenance', (new SessionProvenance)->getTable());
    }
}
