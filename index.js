import express from 'express';
import mysql from 'mysql';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';


const port=5000;

const app= express();


app.use(express.json());
app.use(cors());



const db=mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'123456789',
    database:'mydb'
})





app.post('/signUp',async(req,res)=>{
    try {
        const {name,password,email}=req.body;
        if(!name || !password ||!email){
            res.status(400).send('Please fill all the required fields!');
            return;
        }
        const hashedPassword=await bcrypt.hash(password,10);
        const user={
            name:name,
            email:email,
            password:hashedPassword
        }
        db.query('INSERT INTO users SET ?',user,(err,result)=>{
            if(err){
                if(err.code==='ER_DUP_ENTRY'){
                    res.status(400).send('Username or Email are associated with an existing account!.');
                    return ;
                }
            res.status(500).send('Server error!');
            return ;
            }
            else{
                res.status(200).send('User created successfully!');
                return ;
            }
        })
    } catch (error) {
        res.status(500).send(`System error: ${error}`);
        return ;
    }
})



app.post('/login',async(req,res)=>{
 try {
    const {identifier,password}=req.body;
    if(!identifier ||!password){
        res.status(400).send('Please fill all the required fields!');
        return;
    }
    db.query('SELECT * FROM users WHERE name=? ',[identifier],async(err,results)=>{
        if(err){
            console.log('Server error :',err);
            res.status(500).send('Server error!');
            return;
        }
        if(results.length>0 ){
            if( await bcrypt.compare(password,results[0].password)){
                const token=jwt.sign({name:results[0].name,email:results[0].email},'secret');
                res.status(200).send({token:token});
                return ;
            }
            else{
               res.status(400).send('Invalid credentials!');
               return ;
            }
        }
        else{
        db.query('SELECT * FROM users WHERE  email=?',[identifier],async(err,results)=>{
            if(err){
                console.log('Server error :',err);
                res.status(500).send('Server error!');
                return;
            }
            if(results.length>0){
                if( await bcrypt.compare(password,results[0].password)){
                    const token=jwt.sign({name:results[0].name,email:results[0].email},'secret');
                    res.status(200).send({token:token});
                    return ;
                }
                else{
                   res.status(400).send('Invalid credentials!');
                   return ;
                }
            }
            else{
               res.status(404).send('User does not exist.Please create an account.');
               return ;
            }
        })
        }
    })
 } catch (error) {
    console.log('Server error :',err);
    res.status(500).send('System error');
    return ;
 }        
})



app.listen(port,()=>{
    console.log('listening on port',port);
})