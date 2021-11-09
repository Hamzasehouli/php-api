<?php

namespace app\controllers\personController;

use app\config\DB;
use app\models\personModel\PersonModel;

header('content-type:application/json');
session_start();

class PersonController
{
    public static function isLoggedin()
    {
        $d = json_decode(file_get_contents('php://input'), true);
        if (isset($d)) {
            $resp = explode('=', $d['jwt']);
            $jwt = $resp[1];
            print_r($jwt);
        } else {
            extract($_COOKIE);
            print_r($jwt);
        }
        // split the jwt
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;

        // build a signature based on the header and payload using the secret
        // Encode Header to Base64Url String
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));

        // Encode Payload to Base64Url String
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        // Create Signature Hash
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, 'abC123!', true);

        // Encode Signature to Base64Url String
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        // verify it matches the signature provided in the jwt
        $is_signature_valid = ($base64UrlSignature === $signature_provided);
        // $isTokenValid = null;
        // if ($is_token_expired || !$is_signature_valid) {
        //     $isTokenValid = false;
        // } else {
        //     $isTokenValid = true;
        // }

        header("HTTP/1.1 200");

        var_dump(json_encode([
            'isLoggedin' => $is_signature_valid,
        ]));

    }
    public static function getPeople()
    {

        $db = new DB();
        $con = $db->connect();
        $personModel = new PersonModel();
        $stmt = $personModel->find($con);
        $stmt->execute();
        $temp_people = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        $people = array();
        $people['status'] = 'success';
        $people['results'] = count($temp_people);
        $people['data'] = array();
        $people['data'] = array_map(function ($p) {
            return [
                'id' => $p['id'],
                'username' => $p['username'],
                'email' => $p['email'],
                'password' => $p['password'],
                'added_at' => $p['added_at'],
            ];
        }, $temp_people);
        print_r(json_encode($people));
    }
    public static function createPerson()
    {
        $db = new DB();
        $con = $db->connect();
        $personModel = new PersonModel();
        $stmt = $personModel->create($con);
        $data = json_decode(file_get_contents('php://input'), true);
        // extract($_POST);
        extract($data);
        if (empty($username) || strlen($username) < 3) {
            header("HTTP/1.1 403");
            print_r(json_encode([
                'status' => 'fail',
                'message' => 'Please enter a valid username to continue ',
            ]));
            return;
        }
        if (empty($email) || !strpos($email, '@')) {
            header("HTTP/1.1 403");
            print_r(json_encode([
                'status' => 'fail',
                'message' => 'Please enter a valid email',
            ]));
            return;
        }
        if (empty($password) || strlen($password) < 8) {
            header("HTTP/1.1 403");
            print_r(json_encode([
                'status' => 'fail',
                'message' => 'Please enter a valid password, a valid password must have at least 8 characters',
            ]));
            return;
        }
        $stmt->bindValue(':username', $username);
        $stmt->bindValue(':email', $email);
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt->bindValue(':password', $hashedPassword);
        if ($stmt->execute()) {
            // print_r(json_encode([
            //     'status' => 'success',
            //     'message' => 'You signed up successfully',
            // ]));
            $results = $con->prepare('SELECT * FROM person WHERE username=:username');
            $results->bindValue('username', $username);
            $results->execute();
            $resul = $results->fetch(\PDO::FETCH_ASSOC);

            extract($resul);
            ///////////////////////////////////////////////////////////////////////////////////
            //generate jwt
            // Create token header as a JSON string
            $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);

            // Create token payload as a JSON string
            $payload = json_encode(['user_id' => $id, 'exp' => (time() + (120 * 60))]);

            // Encode Header to Base64Url String
            $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));

            // Encode Payload to Base64Url String
            $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

            // Create Signature Hash
            $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, 'abC123!', true);

            // Encode Signature to Base64Url String
            $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

            // Create JWT
            $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

            // setcookie('jwt', value, expire, path, domain, secure, httponly);

            header("HTTP/1.1 201");
            setcookie('jwt', $jwt, time() + (120 * 60));
            print_r(json_encode([
                'status' => 'success',
                'message' => 'You signed up successfully',
                'jwt' => $jwt,
            ]));
            return;
        }
    }
    public static function getPerson()
    {
        echo 'get person';
        extract($_GET);
        $db = new DB();
        $con = $db->connect();
        $personModel = new PersonModel();
        $stmt = $personModel->findOne($con);
        $stmt->bindValue(':id', $id);
        $stmt->execute();
        $temp_people = $stmt->fetch(\PDO::FETCH_ASSOC);
        $people = array();
        $people['status'] = 'success';
        $people['data'] = array();
        $people['data'] = array_map(function ($p) {
            return [
                'id' => $p['id'],
                'username' => $p['username'],
                'email' => $p['email'],
                'password' => $p['password'],
                'added_at' => $p['added_at'],
            ];
        }, $temp_people);
        print_r(json_encode($people));
    }
    public static function updatePerson()
    {
        echo 'update person';
    }
    public static function deletePerson()
    {
        echo 'delete person';
    }
    public static function login()
    {
        $db = new DB();
        $con = $db->connect();
        $personModel = new PersonModel();
        $stmt = $personModel->findOne($con);
        $data = json_decode(file_get_contents('php://input'), true);
        // extract($_POST);
        extract($data);

        if (empty($username) || empty($password)) {
            header("HTTP/1.1 403");
            print_r(json_encode([
                'status' => 'fail',
                'message' => 'Please enter valid username and password',
            ]));
            return;
        }
        $stmt->bindValue(':username', $username);

        $stmt->execute();
        $resul = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        $row = $stmt->rowCount();
        if ($row < 1) {
            header("HTTP/1.1 404");
            print_r(json_encode([
                'status' => 'fail',
                'message' => 'Either inputs are incorrect or user no longer exist ',
            ]));
            return;
        }

        // print_r($password);
        // print_r($resul[0]["password"]);

        $isPasswordCorrect = password_verify($password, $resul[0]["password"]);
        if (!$isPasswordCorrect) {
            header("HTTP/1.1 404");
            print_r(json_encode([
                'status' => 'fail',
                'message' => 'Either inputs are incorrect or user no longer exist ',
            ]));
            return;
        }

        print_r(json_encode([
            'status' => 'success',
            'message' => 'You logged in successfully',
        ]));
        header("HTTP/1.1 200");
        // echo json_encode([
        //     'status' => 'success',
        //     'message' => 'You logged in successfully',
        // ]);

        // $stmt->bindValue(':username', $username);
        // $stmt->bindValue(':email', $email);
        // $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        // $stmt->bindValue(':password', $hashedPassword);
        // if ($stmt->execute()) {
        //     print_r(json_encode([
        //         'status' => 'success',
        //         'message' => 'Person has been created successfull',
        //     ]));
        // }
    }
}