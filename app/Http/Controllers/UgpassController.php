<?php

namespace App\Http\Controllers;

use App\Services\UgpassService;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class UgpassController extends Controller
{
    public function __construct(private UgpassService $svc) {}
    // Step 1: Redirect to UgPass for authentication

    public function start(Request $request)
    {
        $clientId = config('services.ugpass.client_id');
        $redirect = config('services.ugpass.redirect_uri');
        $authz = config('services.ugpass.authorization');
        $aud = rtrim(config('services.ugpass.authorization_base'), '/'); 

        $requestJwt = $this->svc->buildRequestJwt($clientId, $redirect, $aud);

        $state = bin2hex(random_bytes(8));
        $nonce = bin2hex(random_bytes(8));
        session(['ugpass_state' => $state, 'ugpass_nonce' => $nonce]);

        $query = http_build_query([
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'response_type' => 'code',
            'scope' => config('services.ugpass.scope'),
            'state' => $state,
            'nonce' => $nonce,
            'request' => $requestJwt,
        ]);

        return redirect($authz . '?' . $query);
    }

    public function callback(Request $request)
    {
        $state = $request->get('state');
        if ($state !== session('ugpass_state')) {
            abort(400, 'Invalid state');
        }

        $code = $request->get('code');
        if (!$code) {
            abort(400, 'Missing code');
        }

        // 1) Get UGHub access token
        $ughubTokenRes = Http::asForm()
            ->withBasicAuth(config('services.ughub.client_key'), config('services.ughub.client_secret'))
            ->post(config('services.ughub.token_url'), ['grant_type' => 'client_credentials']);
        if (!$ughubTokenRes->ok()) abort(500, 'UGHub token failed');

        $ughubToken = $ughubTokenRes->json('access_token');

        // 2) Exchange code for UgPass tokens
        $clientId = config('services.ugpass.client_id');
        $redirect = config('services.ugpass.redirect_uri');

        $clientAssertion = $this->svc->buildClientAssertion(
            $clientId,
            config('services.ugpass.token') // token endpoint as aud
        );

        $tokenRes = Http::asForm()
            ->withHeaders(['Authorization' => "Bearer {$ughubToken}"])
            ->post(config('services.ugpass.token'), [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirect,
                'client_id' => $clientId,
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion' => $clientAssertion,
            ]);

        if (!$tokenRes->ok()) {
            return response()->json($tokenRes->json(), $tokenRes->status());
        }

        $ugpassAccessToken = $tokenRes->json('access_token');
        $idToken = $tokenRes->json('id_token');

        // 3) Call UserInfo (two bearer tokens)
        $userinfoRes = Http::withHeaders([
                'Authorization' => "Bearer {$ughubToken}",
                'UgPassAuthorization' => "Bearer {$ugpassAccessToken}",
                'Accept' => 'application/jwt',
            ])->get(config('services.ugpass.userinfo'));

        if (!$userinfoRes->ok()) {
            return response()->json($userinfoRes->json(), $userinfoRes->status());
        }

        // For demo: just show raw responses
        return view('ugpass', [
            'id_token' => $idToken,
            'userinfo_jwt' => $userinfoRes->body(),
        ]);
    }

    public function logout(Request $request)
    {
        $idToken = $request->user()?->id_token ?? $request->get('id_token'); // adapt to your storage
        $url = config('services.ugpass.logout') . '?' . http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => config('app.url'),
            'state' => bin2hex(random_bytes(8)),
        ]);
        return redirect($url);
    }
}
