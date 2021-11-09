<?php

namespace app;

class Router{
    public array $getRoutes;
    public array $postRoutes;

    public function get($route, $fn ){
        $this->getRoutes[$route] = $fn;
        
    }

    public function post($route, $fn ){
        $this->postRoutes[$route] = $fn;
    }

    

    public function run(){

        $currentRoute = $_SERVER['PATH_INFO'] ?? '/';
        $method = $_SERVER['REQUEST_METHOD'];
        $fn=null;
        if($method === 'GET'){
            if(isset($this->getRoutes[$currentRoute])){
                $fn = $this->getRoutes[$currentRoute];
            }
        }else{
            if(isset($this->postRoutes[$currentRoute])){
                $fn = $this->postRoutes[$currentRoute];
            }
        }
        if($fn){
                call_user_func($fn);
        }else{
            echo '404, No page found';
        }

        
    }
}

?>