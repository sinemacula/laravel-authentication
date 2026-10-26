<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Identity contract.
 *
 * Marks a model as a contextual identity. Implementations are typically
 * Eloquent models; sites that need the `Model` surface should express it at the
 * call site via an `Identity&\Illuminate\Database\Eloquent\Model` intersection
 * type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Identity extends Authenticatable {}
