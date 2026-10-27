<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\ClientText;

/**
 * Where a sign-in comes from and what it asks for: the client (its IP address
 * and user agent), the name and platform it gives itself, the principal it
 * wants to act as, and the refresh token it holds for a device it signed in on
 * before.
 *
 * The client name and platform come from the client, so they are made safe to
 * store as `ClientContext` makes the user agent safe: NUL bytes removed,
 * invalid UTF-8 replaced, and cut to the column's 255 characters; a value that
 * is empty after cleaning is `null`.
 *
 * The principal is verified, not trusted: it must resolve through the
 * resolver's hinted path to the same principal of the same class, owned by the
 * identity signing in. The refresh token proves the client holds that device: a
 * sign-in from the same client then continues on the same device instead of
 * creating another (see the session service).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignInContext
{
    /** @var int Longest client name or platform kept, in characters. */
    private const int DESCRIPTION_MAX_LENGTH = 255;

    /** @var ?string Cleaned name the client gave itself. */
    public ?string $clientName;

    /** @var ?string Cleaned platform the client reported. */
    public ?string $platform;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $refreshToken
     */
    public function __construct(

        /** Client the sign-in comes from. */
        public ClientContext $client,

        // Name the client gives itself, such as "Work laptop".
        ?string $clientName = null,

        // Platform the client reports, such as "macOS".
        ?string $platform = null,

        /** Principal the sign-in asks to act as, verified before it is used. */
        public ?Principal $principal = null,

        /** Refresh token the client holds for the device it signed in on before. */
        #[\SensitiveParameter] public ?string $refreshToken = null,
    ) {
        $this->clientName = ClientText::clean($clientName, self::DESCRIPTION_MAX_LENGTH);
        $this->platform   = ClientText::clean($platform, self::DESCRIPTION_MAX_LENGTH);
    }

    /**
     * Read the context of a sign-in from its request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $refreshToken
     * @return self
     */
    public static function fromRequest(
        Request $request,
        ?string $clientName = null,
        ?string $platform = null,
        ?Principal $principal = null,
        #[\SensitiveParameter] ?string $refreshToken = null,
    ): self {
        return new self(ClientContext::fromRequest($request), $clientName, $platform, $principal, $refreshToken);
    }
}
