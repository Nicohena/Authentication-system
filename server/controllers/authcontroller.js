import bycrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';

export const register =async(req,res)=>{
    const {name,email,password}=req.body;
    if (!name || !email || !password){
        return res.json({success:false,message:"All fields are required"});
    } 
    try{
        const existingUser =await userModel.findOne({email});
        if(existingUser){
            return res.status(409).json({success:false,message:"User already exists"});
        }
        const hashedPassword=await bycrypt.hash(password,10);
        const user=new userModel({name,email,password:hashedPassword});
        await user.save();
        

        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ success: false, message: 'JWT_SECRET not configured' });
        }
        const token=jwt.sign({userId:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV==='production'?'none':'strict',
            maxAge:7*24*60*60*1000
        });
        return  res.json({success:true,message:"User registered successfully"});


    }catch(error){
        return res.json({success:false,message:error.message});
    }
}
export const login =async(req,res)=>{
    const {email,password}=req.body;
    if (!email || !password){
        return res.json({success:false,message:"All fields are required"});
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.status(404).json({success:false,message:"User does not exist"});
        }
        const isMatch=await bycrypt.compare(password,user.password);
        if(!isMatch){
            return res.status(401).json({success:false,message:"Invalid credentials"});
        }
        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ success: false, message: 'JWT_SECRET not configured' });
        }
        const token=jwt.sign({userId:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV==='production'?'none':'strict',
            maxAge:7*24*60*60*1000
        });
        return res.json({success:true,message:"Login successful"});

    }catch(error){
        return res.json({success:false,message:error.message});
    }
}

export const logout =async(req,res)=>{
    try{
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV==='production'?'none':'strict',
        });
        return res.json({success:true,message:"Logout successful"});

    }
    catch(error){
        return res.json({success:false,message:error.message});
    }
}

    