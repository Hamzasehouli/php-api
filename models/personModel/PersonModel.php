<?php

namespace app\models\personModel;

class PersonModel
{

    public $id = '';
    public $username = '';
    public $email = '';
    public $password = '';

    public function find($con)
    {
        $query = 'SELECT * FROM person';
        $stmt = $con->prepare($query);
        return $stmt;
    }
    public function create($con)
    {
        $query = 'INSERT INTO person (username, email, password) VALUES(:username, :email, :password)';
        $stmt = $con->prepare($query);
        return $stmt;
    }

    public function findOneById($con)
    {
        $query = 'SELECT * FROM person WHERE username=:username';
        $stmt = $con->prepare($query);
        return $stmt;
    }
    public function findOne($con)
    {
        $query = 'SELECT * FROM person WHERE username=:username';
        $stmt = $con->prepare($query);
        return $stmt;
    }

}