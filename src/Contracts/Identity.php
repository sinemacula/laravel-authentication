<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Identity contract.
 *
 * Marks an Eloquent model as a contextual identity. Implementations
 * carry no methods beyond Laravel's Authenticatable surface; the
 * `@phpstan-require-extends` tag below pins implementations to
 * Eloquent so guards may safely call Eloquent-only methods such as
 * `getKey()` against an `Identity`.
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface Identity extends Authenticatable {}
