<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'resend' => [
        'key' => env('RESEND_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],
     'ugpass' => [
        'client_id' => env('UGPASS_CLIENT_ID'),
        'redirect_uri' => env('UGPASS_REDIRECT_URI'),
        'scope' => env('UGPASS_SCOPE', 'openid urn:idp:digitalid:profile'),
        'authorization' => env('UGPASS_AUTHORIZATION'),
        'authorization_base' => env('UGPASS_AUTHORIZATION', 'https://stgapi.ugpass.go.ug/idp/'),
        'jwks' => env('UGPASS_JWKS'),
        'token' => env('UGPASS_TOKEN'),
        'userinfo' => env('UGPASS_USERINFO'),
        'logout' => env('UGPASS_LOGOUT'),
        'private_key_path' => env('UGPASS_PRIVATE_KEY_PATH', storage_path('keys/ugpass_private.pem')),
    ],
    'ughub' => [
        'token_url' => env('UGHUB_TOKEN_URL'),
        'client_key' => env('UGHUB_CLIENT_KEY'),
        'client_secret' => env('UGHUB_CLIENT_SECRET'),
    ],

];
