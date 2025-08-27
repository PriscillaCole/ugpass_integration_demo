<?php

namespace App\Services;

use Firebase\JWT\JWT;
use Ramsey\Uuid\Uuid;

class UgpassService
{
    public function buildRequestJwt(string $clientId, string $redirectUri, string $aud): string
    {
        $now = time();
        $payload = [
            'iss' => $clientId,
            'aud' => $aud,
            'iat' => $now,
            'exp' => $now + 600,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => config('services.ugpass.scope'),
            'state' => bin2hex(random_bytes(8)),
            'nonce' => bin2hex(random_bytes(8)),
        ];
        $privateKey = file_get_contents(config('services.ugpass.private_key_path'));
        return JWT::encode($payload, $privateKey, 'RS256');
    }

    public function buildClientAssertion(string $clientId, string $aud): string
    {
        $now = time();
        $payload = [
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => $aud,
            'iat' => $now,
            'exp' => $now + 600,
            'jti' => Uuid::uuid4()->toString(),
        ];
        $privateKey = file_get_contents(config('services.ugpass.private_key_path'));
        return JWT::encode($payload, $privateKey, 'RS256');
    }
}
