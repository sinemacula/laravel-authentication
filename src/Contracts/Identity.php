<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Marks a model as a contextual identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Identity extends Authenticatable {}
