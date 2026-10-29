<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a client credentials exchange issues an access token, at
 * once: the exchange writes nothing but a throttled last-use time, so there is
 * no commit to wait for. No device is created and no refresh token issued.
 *
 * The context carries the `jwt` guard the token is for, the client of the
 * request, the non-human identity, the principal and its tenant, method
 * `client_credentials`, the API key's id in `credentialId` and the scopes the
 * token grants. Never the client secret or the token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientCredentialsGranted extends ContextEvent {}
