<?php

namespace app\config;

use PDO;
use PDOException;

class DB{
    protected $localhost = 'localhost';
    protected $port = 3306;
    protected $dbname ='people' ;
    protected $username = 'root';
    protected $password = '';
    public $con =null;

    public function connect(){
        try{
            $this->con = new PDO("mysql:host=$this->localhost;port=$this->port;dbname=$this->dbname",$this->username, $this->password);
            $this->con->setAttribute(PDO::ERRMODE_EXCEPTION, PDO::ATTR_ERRMODE);
            return $this->con;
        }catch(PDOException $err){
            'Connection with database failed:' . $err->getMessage();
        }

    }
}

?>