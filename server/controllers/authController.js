
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';


export const register= async(req,res)=>{
    const{name,email,password}=req.body;

    if(!name || !email || !password){
        return res.json({sucess: false, message: "missing details"});

    }
    try{
        const existingUser= await userModel.findOne({
            email
        }) 
        if(existingUser){
            return res.json({sucess: false, message: "user already exists"});
        }

        const hashPassword=await bcrypt.hash(password,10);

        const user= await userModel.create({
            name,
            email,
            password: hashPassword,
        });
        await user.save();


        const token=jwt.sign({id:user._id}, process.env.JWT_SECRET,{expiresIn:'3d'});
        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict' ,
            maxAge:3*24*60*60*1000,
        });

        return res.json({sucess: true, message: "registration successful"});   




    }catch (error){
        return res.json({sucess: false, message: error.message});
    }
}

export const login= async(req,res)=>{
    const{email,password}=req.body;
    if(!email || !password){
        return res.json({sucess: false, message: "email and password required"});
    }
    try{
        const user= await userModel.findOne({
            email
        })
        if(!user){
            return res.json({sucess: false, message: "invalid email"});
        }
        const isMatch= await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.json({sucess: false, message: "invalid password"});
        }

        const token=jwt.sign({id:user._id}, process.env.JWT_SECRET,{expiresIn:'3d'});
        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict' ,
            maxAge:3*24*60*60*1000,
        });


        return res.json({sucess: true, message: "login successful"});   


    } catch (error){
        return res.json({sucess: false, message: error.message});
    }
}


export const logout= async(req,res)=>{
    try{
        res.cookie('token','',{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict' ,
            expires: new Date(0)
        })
        return res.json({sucess: true, message: "logout successful"});

    }catch (error){
        return res.json({sucess: false, message: error.message});
    }
}

