<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl">UgPass Test</h2>
    </x-slot>

    <div class="p-6">
        <h3 class="text-lg font-bold mb-2">ID Token (JWT)</h3>
        <pre class="p-3 bg-gray-100 rounded">{{ $id_token }}</pre>

        <h3 class="text-lg font-bold mt-6 mb-2">UserInfo (signed JWT)</h3>
        <pre class="p-3 bg-gray-100 rounded">{{ $userinfo_jwt }}</pre>
    </div>
</x-app-layout>
