<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");

require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';

use app\config\DB;
use app\controllers\personController\PersonController;
use app\Router;

print_r($_COOKIE);

$db = new DB();
$con = $db->connect();
$router = new Router();
$router->get("/api/v1/people", [PersonController::class, 'getPeople']);
$router->post("/api/v1/people", [PersonController::class, 'createPerson']);
$router->post("/api/v1/auth/login", [PersonController::class, 'login']);
$router->post("/api/v1/auth/isLoggedin", [PersonController::class, 'isLoggedin']);
$router->get("/api/v1/people/getperson", [PersonController::class, 'getPerson']);
$router->post("/api/v1/people/updateperson", [PersonController::class, 'updatePerson']);
$router->post("/api/v1/people/deleteperson", [PersonController::class, 'deletePerson']);

$router->run();