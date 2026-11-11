<?php

declare(strict_types = 1);

namespace Tests\Unit\ClientCredentials;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest;
use SineMacula\Laravel\Authentication\ClientCredentials\Enums\ClientAuthentication;
use SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient;
use Symfony\Component\Process\Process;

/**
 * Unit tests for reading a client credentials token request as RFC 6749 defines
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientCredentialsRequest::class)]
#[CoversClass(PresentedClient::class)]
final class ClientCredentialsRequestTest extends TestCase
{
    /** @var string Reads the request a body and its parameters make, in a PHP process of its own, and prints the result. */
    private const string READER = <<<'PHP'
        require $argv[1];

        $request = Illuminate\Http\Request::create('/oauth/token', 'POST', json_decode($argv[3], true), [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], $argv[2]);
        $read    = SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest::extract($request);

        echo is_string($read) ? $read : json_encode([$read->clientId, $read->scope]);
        PHP;

    /**
     * Body credentials and a scope are read where the application allows
     * `client_secret_post`.
     *
     * @return void
     */
    public function testReadsBodyCredentialsAndAScope(): void
    {
        $presented = ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=id&client_secret=secret&scope=a+b'));

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame('id', $presented->clientId);
        self::assertSame('secret', $presented->clientSecret());
        self::assertSame('a b', $presented->scope);
    }

    /**
     * The extraction records whether Basic or body credentials authenticated
     * the client.
     *
     * @return void
     */
    public function testRecordsHowTheClientAuthenticated(): void
    {
        $header    = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:secret')];
        $post      = ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=id&client_secret=secret'));
        $withBasic = ClientCredentialsRequest::extract(self::request('grant_type=client_credentials', $header));

        self::assertInstanceOf(PresentedClient::class, $post);
        self::assertSame(ClientAuthentication::POST, $post->authentication);
        self::assertInstanceOf(PresentedClient::class, $withBasic);
        self::assertSame(ClientAuthentication::BASIC, $withBasic->authentication);
        self::assertSame('invalid_client', ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=id')));
        self::assertSame('invalid_request', ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=id', $header)));
    }

    /**
     * A parameter sent without a value is treated as omitted (RFC 6749 section
     * 3.1).
     *
     * @return void
     */
    public function testAParameterWithoutAValueIsOmitted(): void
    {
        $basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:secret')];

        self::assertSame('invalid_request', ClientCredentialsRequest::extract(self::request('grant_type=&client_id=id&client_secret=secret')));
        self::assertSame('invalid_client', ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=&client_secret=')));
        self::assertSame('invalid_client', ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=id&client_secret=')));

        $presented = ClientCredentialsRequest::extract(self::request('grant_type=client_credentials&client_id=&client_secret=&scope=', $basic));

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame('id', $presented->clientId);
        self::assertNull($presented->scope);
    }

    /**
     * Basic credentials are read form-url-decoded, whatever the scheme's case,
     * and a secret may hold a colon.
     *
     * @return void
     */
    public function testReadsBasicCredentials(): void
    {
        $basic     = ['HTTP_AUTHORIZATION' => 'basic ' . base64_encode('my%20id:se%3Acr+et:x')];
        $request   = self::request('grant_type=client_credentials', $basic, 'application/x-www-form-urlencoded; charset=UTF-8');
        $presented = ClientCredentialsRequest::extract($request);

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame('my id', $presented->clientId);
        self::assertSame('se:cr et:x', $presented->clientSecret());
        self::assertNull($presented->scope);
    }

    /**
     * Rows of `[body, server, content type, query, client id, secret, scope]`:
     * requests in form, where the application allows `client_secret_post`.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string, 3: array<string, string>, 4: string, 5: string, 6: ?string}>
     */
    public static function provideClients(): iterable
    {
        $form  = 'application/x-www-form-urlencoded';
        $mixed = ' Application/X-WWW-Form-Urlencoded ;charset=utf-8';
        $body  = 'grant_type=client_credentials&client_id=id&client_secret=secret';
        $basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:secret')];
        $colon = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:se:cret')];

        yield from [
            'body credentials'           => ["{$body}&scope=a", [], $form, [], 'id', 'secret', 'a'],
            'basic credentials'          => ['grant_type=client_credentials&scope=a+b', $basic, $form, [], 'id', 'secret', 'a b'],
            'a colon in a basic secret'  => ['grant_type=client_credentials', $colon, $form, [], 'id', 'se:cret', null],
            'a media type in any case'   => [$body, [], $mixed, [], 'id', 'secret', null],
            'another query parameter'    => [$body, [], $form, ['page' => '2'], 'id', 'secret', null],
            'another parameter repeated' => ["{$body}&x=1&x=2", [], $form, [], 'id', 'secret', null],
        ];
    }

    /**
     * A form request presents its client and scope, ignoring any other
     * parameter.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $type
     * @param  array<string, string>  $query
     * @param  string  $id
     * @param  string  $secret
     * @param  ?string  $scope
     * @return void
     */
    #[DataProvider('provideClients')]
    public function testReadsAClientInForm(string $body, array $server, string $type, array $query, string $id, #[\SensitiveParameter] string $secret, ?string $scope): void
    {
        $request = self::request($body, $server, $type);

        $request->query->add($query);

        $presented = ClientCredentialsRequest::extract($request);

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame([$id, $secret, $scope], [$presented->clientId, $presented->clientSecret(), $presented->scope]);
    }

    /**
     * Rows of `[body, server, content type, method, error]`.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string, 3: string, 4: string}>
     */
    public static function provideRefusedRequests(): iterable
    {
        $form  = 'application/x-www-form-urlencoded';
        $body  = 'grant_type=client_credentials&client_id=id&client_secret=secret';
        $basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:secret')];

        yield from [
            'a GET'                 => [$body, [], $form, 'GET', 'invalid_request'],
            'a JSON body'           => [$body, [], 'application/json', 'POST', 'invalid_request'],
            'a multipart body'      => [$body, [], 'multipart/form-data', 'POST', 'invalid_request'],
            'no content type'       => [$body, [], '', 'POST', 'invalid_request'],
            'an empty body'         => ['', [], $form, 'POST', 'invalid_request'],
            'a parameter twice'     => ["{$body}&scope=a&scope=b", [], $form, 'POST', 'invalid_request'],
            'an encoded repeat'     => ["{$body}&client%5Fid=id", [], $form, 'POST', 'invalid_request'],
            'a dotted repeat'       => ["client.id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a spaced repeat'       => ["client+id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a padded repeat'       => ["+client_id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a list then a value'   => ["client_id[]=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'an unclosed bracket'   => ["client[id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a list'                => ["{$body}&scope[]=a", [], $form, 'POST', 'invalid_request'],
            'no grant'              => ['client_id=id&client_secret=secret', [], $form, 'POST', 'invalid_request'],
            'another grant'         => ['grant_type=password&client_id=id&client_secret=secret', [], $form, 'POST', 'unsupported_grant_type'],
            'basic and a body id'   => ['grant_type=client_credentials&client_id=id', $basic, $form, 'POST', 'invalid_request'],
            'basic and a secret'    => ['grant_type=client_credentials&client_secret=s', $basic, $form, 'POST', 'invalid_request'],
            'no client'             => ['grant_type=client_credentials', [], $form, 'POST', 'invalid_client'],
            'only a secret'         => ['grant_type=client_credentials&client_secret=s', [], $form, 'POST', 'invalid_client'],
            'basic not base64'      => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic %%%'], $form, 'POST', 'invalid_client'],
            'basic without a colon' => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('idsecret')], $form, 'POST', 'invalid_client'],
            'basic alone'           => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic'], $form, 'POST', 'invalid_client'],
            'a bearer instead'      => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Bearer token'], $form, 'POST', 'invalid_client'],
        ];
    }

    /**
     * A request not in form is refused with its RFC 6749 error, whether the
     * application allows `client_secret_post` or not.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $type
     * @param  string  $method
     * @param  string  $error
     * @return void
     */
    #[DataProvider('provideRefusedRequests')]
    public function testRefusesARequestNotInForm(string $body, array $server, string $type, string $method, string $error): void
    {
        self::assertSame($error, ClientCredentialsRequest::extract(self::request($body, $server, $type, $method)));
    }

    /**
     * Any parameter in the query string is refused, the body's included.
     *
     * @return void
     */
    public function testRefusesAParameterInTheQueryString(): void
    {
        foreach (['grant_type', 'scope', 'client_id', 'client_secret'] as $name) {
            $request = self::request('grant_type=client_credentials&client_id=id&client_secret=secret');

            $request->query->set($name, 'x');

            self::assertSame('invalid_request', ClientCredentialsRequest::extract($request), $name);
        }
    }

    /**
     * Each parameter given again under a name PHP cuts at a NUL byte is a
     * repeat, refused like any other, even with the same value.
     *
     * @return void
     */
    public function testRefusesARepeatUnderANameCutAtANulByte(): void
    {
        $body = 'grant_type=client_credentials&client_id=id&client_secret=secret&scope=a';

        foreach (['grant_type' => 'client_credentials', 'scope' => 'a', 'client_id' => 'id', 'client_secret' => 'secret'] as $name => $value) {
            self::assertSame('invalid_request', ClientCredentialsRequest::extract(self::request("{$body}&{$name}%00x={$value}")), $name);
        }

        self::assertInstanceOf(PresentedClient::class, ClientCredentialsRequest::extract(self::request("{$body}&extra%00x=1")));
    }

    /**
     * Rows of `[separator, body, parameters, result]` for bodies read under
     * another `arg_separator.input`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: array<string, string>, 3: string}>
     */
    public static function provideBodiesUnderAnotherSeparator(): iterable
    {
        $body       = 'grant_type=client_credentials&client_id=id&client_secret=secret';
        $parameters = ['grant_type' => 'client_credentials', 'client_id' => 'id', 'client_secret' => 'secret'];

        yield from [
            'a separator in a value'     => ['&;', "{$body}&scope=read;client_id=x", $parameters + ['scope' => 'read;client_id=x'], '["id","read;client_id=x"]'],
            'a repeat'                   => ['&;', "{$body}&scope=a&scope=b", $parameters + ['scope' => 'b'], 'invalid_request'],
            'a repeat cut at NUL'        => ['&;', "{$body}&client_id%00x=id", $parameters, 'invalid_request'],
            'a separator in a name'      => ['&_', "{$body}&client_id=last", ['client_id' => 'last'] + $parameters, 'invalid_request'],
            'a separator in an encoding' => ['&%', "{$body}&+client_id=last", ['client_id' => 'last'] + $parameters, 'invalid_request'],
        ];
    }

    /**
     * Repeats are found among the pairs a form body is split into on `&` alone,
     * whatever else `arg_separator.input` splits a query string on.
     *
     * @param  string  $separator
     * @param  string  $body
     * @param  array<string, string>  $parameters
     * @param  string  $result
     * @return void
     */
    #[DataProvider('provideBodiesUnderAnotherSeparator')]
    public function testFindsRepeatsAsAFormBodyIsSplit(string $separator, string $body, array $parameters, string $result): void
    {
        $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
        $process  = new Process([PHP_BINARY, '-d', "arg_separator.input={$separator}", '-r', self::READER, '--', $autoload, $body, json_encode($parameters, JSON_THROW_ON_ERROR)]);

        $process->mustRun();

        self::assertSame($result, $process->getOutput());
    }

    /**
     * Every name a pair can be given is compared as PHP's own parser reads it.
     *
     * @return void
     */
    public function testReadsEveryNameAsPhpDoes(): void
    {
        $body    = 'grant_type=client_credentials&client_id=id&client_secret=secret&scope=a';
        $misread = array_filter(self::names(4), static function (string $name) use ($body): bool {
            parse_str("{$name}=x", $read);

            $repeats = in_array(array_key_first($read), ['grant_type', 'scope', 'client_id', 'client_secret'], true);

            return $repeats !== (ClientCredentialsRequest::extract(self::request("{$name}=x&{$body}")) === 'invalid_request');
        });

        self::assertSame([], array_values($misread));
    }

    /**
     * A `null` parameter is absent and any other parameter is ignored.
     *
     * @return void
     */
    public function testANullParameterIsAbsentAndOthersAreIgnored(): void
    {
        $request = self::request('grant_type=client_credentials&client_id=id&client_secret=secret&scope=&extra[]=1');

        $request->request->set('scope', null);

        $presented = ClientCredentialsRequest::extract($request);

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertNull($presented->scope);
    }

    /**
     * Only an Authorization header with the Basic scheme, in any case, counts
     * as Basic: anything else leaves the body credentials to be read.
     *
     * @return void
     */
    public function testRecognizesTheBasicScheme(): void
    {
        $body = 'grant_type=client_credentials&client_id=body&client_secret=secret';

        foreach (['Basic ' . base64_encode('id:s'), 'BASIC ' . base64_encode('id:s')] as $header) {
            self::assertSame('invalid_request', ClientCredentialsRequest::extract(self::request($body, ['HTTP_AUTHORIZATION' => $header])), $header);
        }

        self::assertSame('invalid_client', ClientCredentialsRequest::extract(self::request('grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'BASIC'])));

        foreach (['Basically abc', 'Bearer abc', 'Bearer Basic abc'] as $header) {
            $presented = ClientCredentialsRequest::extract(self::request($body, ['HTTP_AUTHORIZATION' => $header]));

            self::assertInstanceOf(PresentedClient::class, $presented, $header);
            self::assertSame('body', $presented->clientId);
        }
    }

    /**
     * The reader holds no state and cannot be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ClientCredentialsRequest::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ClientCredentialsRequest::class, $instance);
    }

    /**
     * Every name of one to the given number of parts, each a word, a character
     * PHP reads specially in a name, or an encoded one.
     *
     * @param  int  $parts
     * @return list<string>
     */
    private static function names(int $parts): array
    {
        $words = ['client', 'id', 'scope', '_', '.', ' ', '+', '[', ']', '%00'];
        $names = [];
        $last  = [''];

        for ($count = 1; $count <= $parts; $count++) {
            $last  = array_merge(...array_map(static fn (string $name): array => array_map(static fn (string $word): string => $name . $word, $words), $last));
            $names = [...$names, ...$last];
        }

        return $names;
    }

    /**
     * A request with the body, parsed as PHP parses a form, and kept raw.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $type
     * @param  string  $method
     * @return \Illuminate\Http\Request
     */
    private static function request(string $body, array $server = [], string $type = 'application/x-www-form-urlencoded', string $method = 'POST'): Request
    {
        parse_str($body, $parameters);

        return Request::create('/oauth/token', $method, $method === 'POST' ? $parameters : [], [], [], ['CONTENT_TYPE' => $type, ...$server], $body);
    }
}
