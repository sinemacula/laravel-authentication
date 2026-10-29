<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Illuminate\Http\Request;
use Illuminate\Routing\UrlGenerator;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The signed links that confirm identifier changes: a link to a route of the
 * application's, signed by Laravel's URL generator, whose query carries the
 * guard, the identity, the identifier type, the purpose `change_identifier`,
 * the change request and the SHA-256 digest of the new identifier in its normal
 * form, so it confirms that one request of that identity and nothing else, and
 * stops working when a newer request replaces it. It expires with the request.
 *
 * Every field must reach the confirmation in the query string, so the route's
 * own parameters may not take a reserved name, and its path may not take one as
 * a placeholder; both are checked before a change is requested.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChangeLinks
{
    /** @var string The purpose a change link is signed for. */
    public const string PURPOSE = 'change_identifier';

    /** @var list<string> Query parameters the link sets, which the application's own may not use. */
    public const array RESERVED_PARAMETERS = ['guard', 'identity', 'type', 'purpose', 'request', 'hash', 'expires', 'signature'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Routing\UrlGenerator  $urls
     */
    public function __construct(

        /** Signs and checks the links. */
        private UrlGenerator $urls,
    ) {}

    /**
     * Check that the named route can carry a change link: the application's
     * parameters use no reserved name, and a URL of the route carries every
     * reserved name in its query string. A route that does not exist throws as
     * Laravel's URL generator does.
     *
     * @param  string  $route
     * @param  array<string, mixed>  $parameters
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function assertRoute(string $route, array $parameters): void
    {
        $reserved = array_intersect(array_keys($parameters), self::RESERVED_PARAMETERS);

        if ($reserved !== []) {
            throw new \InvalidArgumentException('Identifier change link parameters may not use the reserved names: ' . implode(', ', $reserved) . '.');
        }

        parse_str((string) parse_url($this->urls->route($route, [...$parameters, ...array_fill_keys(self::RESERVED_PARAMETERS, 'reserved')]), PHP_URL_QUERY), $query);

        $placeholders = array_diff(self::RESERVED_PARAMETERS, array_keys($query));

        if ($placeholders !== []) {
            throw new \InvalidArgumentException("Identifier change route [{$route}] may not use the reserved names as placeholders: " . implode(', ', $placeholders) . '.');
        }
    }

    /**
     * Sign a link to the named route that confirms the requested change of the
     * identity, through the guard, until the change expires.
     *
     * @param  string  $route
     * @param  array<string, mixed>  $parameters
     * @param  string  $guard
     * @param  string  $identity
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\RequestedChange  $change
     * @return string
     */
    public function sign(string $route, array $parameters, string $guard, string $identity, RequestedChange $change): string
    {
        return $this->urls->temporarySignedRoute($route, $change->expiresAt, [
            ...$parameters,
            'guard'    => $guard,
            'identity' => $identity,
            'type'     => $change->type,
            'purpose'  => self::PURPOSE,
            'request'  => $change->requestId,
            'hash'     => self::digest($change->identifier),
        ]);
    }

    /**
     * The fields of a request to a change link, or why it is not one: a link
     * whose signature is correct but whose time has passed is `link_expired`;
     * any other bad signature, purpose or field is `invalid_credentials`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\IdentifierChanges\PresentedChangeLink
     */
    public function read(Request $request): FailureReason|PresentedChangeLink
    {
        $link = PresentedChangeLink::of($request);

        if ($link === null || $request->query('purpose') !== self::PURPOSE || !$this->urls->hasCorrectSignature($request)) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        return $this->urls->signatureHasNotExpired($request) ? $link : FailureReason::LINK_EXPIRED;
    }

    /**
     * The digest a link carries for the new identifier: SHA-256 of its normal
     * form.
     *
     * @param  string  $identifier
     * @return string
     */
    public static function digest(#[\SensitiveParameter] string $identifier): string
    {
        return hash('sha256', $identifier);
    }
}
