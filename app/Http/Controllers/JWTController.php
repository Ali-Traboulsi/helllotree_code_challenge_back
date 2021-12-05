<?php

namespace App\Http\Controllers;

use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Auth;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;


class JWTController extends Controller
{
    /**
     * Get the token array structure.
     *
     * @param string $token
     *
     * @return JsonResponse
     */
    protected function respondWithToken($token, $user)
    {
        return response()->json([
            'access_token' => $token,
            'user' => $user,
            'token_type' => 'bearer',
            'status' => 200
        ]);
    }

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Register user.
     *
     * @return JsonResponse
     */
    public function register(Request $request)
    {

        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|min:2|max:100',
                'phone' => 'required|phone:AUTO,US,LB,GB,BE',
                'email' => 'required|string|email|max:100|unique:users',
                'password' => 'required|string|confirmed|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 400);
            }

            $user = User::create([
                'name' => $request->get('name'),
                'phone' => $request->get('phone'),
                'email' => $request->get('email'),
                'password' => Hash::make($request->password)
            ]);

            return response()->json([
                'message' => 'User successfully registered',
                'user' => $user
            ], 201);

        } catch (QueryException $exception) {
            $errorInfo = $exception->errorInfo;
            return response()->json([
                'error' => true,
                'message' => "Internal error occured",
                'errormessage' => $errorInfo
            ], 500);
        }

    }


    /**
     * login user
     *
     * @return JsonResponse
     */
    public function login(Request $request)
    {
        $input = $request->only('email', 'password');

        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            if (!$token = auth()->attempt($input)) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            $user = auth()->user();

            return $this->respondWithToken($token, $user);

        } catch (JWTException $e) {
            $errorInfo = $e->errorInfo;
            return response()->json([
                'error' => true,
                'message' => "Internal error occured",
                'errormessage' => $errorInfo
            ], 500);
        }

    }

    /**
     * Logout user
     *
     * @return JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'User successfully logged out.']);
    }

    /**
     * Refresh token.
     *
     * @return JsonResponse
     */
    public function refresh()
    {
        try {
            // see how you can get the bearer token and check if exists or is valid
            return $this->respondWithToken(auth()->refresh());

        } catch (JWTException $e) {
            $errorInfo = $e->errorInfo;
            return response()->json([
                'error' => true,
                'message' => "Internal error occured",
                'errormessage' => $errorInfo
            ], 500);
        }
    }


    /**
     * Get user profile.
     *
     * @return JsonResponse
     */
    public function profile()
    {
        // also see how you can return an error in case the user is not logged out
        return response()->json(auth()->user());
    }


}
