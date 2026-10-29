<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Machine identity contract.
 *
 * Marks an identity as non-human: an API client or a service account. Such an
 * identity has no password, no interactive sign-in and no device: it
 * authenticates only with a credential issued to it (an API key, or a client
 * credentials exchange), each bound to one principal in one tenant, and the
 * package refuses it on every path that signs in, starts, continues or switches
 * a session.
 *
 * Declared on the identity's own class, so machines are identities of their own
 * type rather than flagged rows of the human one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface MachineIdentity extends Identity {}
