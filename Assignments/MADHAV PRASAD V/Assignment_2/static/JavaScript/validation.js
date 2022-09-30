function valid(){
    var pwd = document.getElementById("pass");
    var cpwd = document.getElementById("cpass"); 

    if(pwd.value != cpwd.value){
        alert("Password does't Match");
        return false;
   }
   return true;
}