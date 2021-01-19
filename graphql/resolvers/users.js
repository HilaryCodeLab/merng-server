const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {UserInputError} = require('apollo-server');
const {SECRET_KEY} = require('../../config');
const {validateRegisterInput, validateUserInput} = require('../../utils/validators');
const User = require('../../models/User');
const Post = require('../../models/Post');

function generateToken(user){
    return jwt.sign(
        {
            id : user.id,
            email: user.email,
            username: user.username
        },
        SECRET_KEY,
        {expiresIn : '1h'}
    );
}
module.exports = {
    Mutation: {
        async login( _,{username, password})
        {
            const {errors, valid} = validateUserInput(username, password);

            if(!valid){
                errors.general = "user does not exist";
                throw new UserInputError("user does not exist", {errors});      
            }

            const user = await User.findOne({username});
            if(!user){
              errors.general = "user is not found";
              throw new UserInputError("user is not found", {errors});      
            }
            const match = await bcrypt.compare(password, user.password);
            if (!match){
                errors.general = "wrong password";
                throw new UserInputError("wrong password", {errors});
            }
            const token = generateToken(user);
            return {
                ...user._doc,
                id : user._id,
                token
            };
        },
        async register(
            _, 
            { 
                registerInput: { username, email, password, confirmPassword } 
            }
            ){
                //Validate user data
                const { errors, valid } = validateRegisterInput(username, email, password, confirmPassword)
                if(!valid){
                    throw new UserInputError('Errors',{errors});
                } 
                //Make sure user does not exist
                const user = await User.findOne({username});

                if(user){
                    throw new UserInputError('user is already taken', {
                        errors: {
                            username: 'this username is taken'
                        }
                    }) ;
                    

                }
                //Hash password and create auth token
                
                password = await bcrypt.hash(password, 12);

                const newUser = new User({
                    username,
                    email,
                    password,
                    createdAt: new Date().toISOString()
                }); 
                
                const res = await newUser.save();
                const token = generateToken(res);
                return {
                    ...res._doc,
                    id : res._id,
                    token
                };
            }
        }
    

};