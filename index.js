const express = require("express");
const app = express();
app.use(express.json()) //middleware for take the incoming json data
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

let db = null

dotenv.config() //loading the .env file

const mongoURL = process.env.Mongo_URL //getting the value from .env file
const secretCode = process.env.secret_code //getting the value from .env file

const initialize = async () => { //function to connect to MongoDB and start the server
    try {
        db = await mongoose.connect(mongoURL) //connecting to MongoDB
        console.log("MongoDB connected")
        
        db.model("User", new mongoose.Schema({ //creating a model for User
            name: String, //defining the schema
            email: String,
            password: String
        }))

        app.listen(4000, ()=>{ //starting the server
            console.log("Server started at port 4000")
        })
    }catch (error) {
        console.log("Error while connecting to MongoDB", error)
    }
}

initialize() //calling the function to connect to MongoDB and start the server

//Authorization Middleware

const authorize = (req, res, next) => {
     const {authorization} = req.headers;
    if(!authorization){ //checking if authorization header is present
        return res.status(401).json({ message: "Please provide authorization header" });
    }
    const token = authorization.split(" ")[1]; //getting the token from authorization header
    if(!token){ //checking if token is present
        return res.status(401).json({ message: "Please provide a token" });
    }else{ 
        const validToken = jwt.verify(token, secretCode) //verifying the token with the secret code
        if(!validToken){ //checking if token is valid
            return res.status(401).json({ message: "Invalid token" });
        }else{
            next() //calling the next middleware or route handler
        }
}
}

//GET Route - we will fetch all the users
app.get("/", authorize, async (req, res) => {
    const users = await db.model("User").find() //fetching all the users from the database
    if(users.length === 0){ //checking if there are no users
        return res.status(404).json({ message: "No users found" });
    }
    else{ 
        return res.status(202).json({ 
            message: "User fetched successfully", 
            data: users //sending the users as response
        });
    }
})

//POST Route - we will create a new user
app.post("/post",authorize, async (req, res) => {
    const { name, email,password } = req.body; //getting the name and email from the request body
     if(!name || !email || !password){ { //checking if name and email are present
        return res.status(400).json({ message: "Name and email are required" });
     } } else {
       //creating a new user
        const addingData = await db.model("User").create({ name, email, password })
        return res.status(201).json({ 
            message: "User created successfully", 
            data: addingData //sending the created user as response
        });
     }
})

app.put("/:id",authorize, async (req, res) => {
    const { id } = req.params;
    const { name, email,password } = req.body;
    if(!name || !email || !password){
        return res.status(400).json({ message: "Name and email are required" });
     } else {
        const updatingData = await db.model("User").findByIdAndUpdate(id, 
            { name, email,password });
        return res.status(200).json({ 
            message: "User updated successfully", 
            data: updatingData });
     }
})

//DELETE Route - we will delete a user
app.delete("/:id",authorize, async (req, res) => {
    const { id } = req.params; //getting the id from the request parameters
    const deletingData = await db.model("User").findByIdAndDelete(id); //deleting the user from the database
    return res.status(200).json({ 
        message: "User deleted successfully", 
        data: deletingData //sending the deleted user as response
    });
})

//Register Routes
app.post("/register", async (req, res) => {
    const { name, email,password } = req.body;
    if(!name || !email || !password){
        return res.status(400).json({ message: "Name and email are required" });
     } else {
        const usersDetails = await db.model("User").find({ email })
        if(usersDetails.length > 0){
            return res.status(400).json({ message: "User already exists" });
        } else{
            const hashedPassword = await bcrypt.hash(password, 10);
            console.log(hashedPassword)
            const addingData = await db.model("User").create({ 
        name, 
        email, 
        password: hashedPassword })
        return res.status(201).json({ 
            message: "User registered successfully", 
            data: addingData });
        }
     
}})

//Login Route
app.post("/login", async (req, res) => {
    const { email,password } = req.body; //getting the email and password from the request body
    if(!email || !password){ //checking if email and password are present
        return res.status(400).json({ message: "email and password are required" });
    } else {
        if (email.includes("@")) { //simple email validation
            if(password.length >= 6){ //checking if password is at least 6 characters long
                const userDetails = await db.model("User").findOne({ email }) //fetching the user from the database
                if(userDetails){ //checking if user exists
                    const isPasswordValid = await bcrypt.compare(password, userDetails.password); //comparing the password with the hashed password
                    if(isPasswordValid){ //checking if password is valid
                        //generating a JWT token
                        const PAYLOAD = { 
                            email: userDetails.email 
                        };
                        const token = jwt.sign(PAYLOAD, secretCode, { expiresIn: "1h" }); 
                        //signing the token with the secret code and setting the expiration time to 1 hour
                        
                        res.status(200).json({ 
                            message: "Login successful", 
                            jwToken: token //sending the token as response
                        });
                    } else{
                        return res.status(400).json({ message: "Invalid password" });
                    }
                } else{
                    return res.status(400).json({ message: "User does not exist" });
                }
            } else{
                return res.status(400).json({ message: "Password must be at least 6 characters long" });
            }

        } else{
            return res.status(400).json({ message: "Invalid email format" });
        }
    }
})