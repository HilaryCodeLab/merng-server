module.exports.validateRegisterInput = (
    username,
    email,
    password,
    confirmPassword
) => {
    const errors = {};
    if(username.trim() === ""){
        errors.username = "username cannot be empty";
    }
    if(email.trim() === ""){
        errors.email = "email cannot be empty";
    }else{
        const regEx = /^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$/;
        if(!email.match(regEx)){
            errors.email = "email is invalid";
        }
    }
    if(password === ""){
        errors.password = "password cannot be empty";
    }else if (password !== confirmPassword){
        errors.confirmPassword = "password must match";
    }
    return{
        errors,
        valid: Object.keys(errors).length < 1
    }

}

module.exports.validateUserInput = (username, password) =>{
    const errors = {};
    if (username.trim() === ""){
        error.username = "username cannot be empty";
    }
    if(password.trim() === ""){
        error.password = "password cannot be empty";
    }
    return{
        errors,
        valid: Object.keys(errors).length < 1
    }
}