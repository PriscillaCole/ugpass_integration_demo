<?php

use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UgpassController;


Route::get('/', function () {
    return view('welcome');
});

Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');

Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');
});
Route::get('/ugpass/login', [UgpassController::class, 'start'])->name('ugpass.start');
Route::get('/ugpass/callback', [UgpassController::class, 'callback'])->name('ugpass.callback');
Route::post('/ugpass/logout', [UgpassController::class, 'logout'])->name('ugpass.logout');
require __DIR__.'/auth.php';
