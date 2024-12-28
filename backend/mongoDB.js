const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const ObjectId = mongoose.Types.ObjectId;


const UserSchema = mongoose.Schema({
    username: {type: String, required: true, unique: true, minLength: 4, maxLength: 12},
    password: {type: String, required: true, match: /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^A-Za-z0-9]).{8,20}$/},
    privateKey: {
        type: [Number],
        required: true,
        validate: {
            validator: function(arr) {
                return arr.length === 64 && 
                       arr.every(num => Number.isInteger(num) && num >= 0 && num <= 255);
            },
            message: 'Private key must be an array of 64 integers between 0 and 255'
        }
    },
    publicKey: {
        type: String,
        required: true
    }
});

// Add this to see validation errors in detail
UserSchema.post('save', function(error, doc, next) {
    if (error.name === 'ValidationError') {
        console.log('Validation Error:', error);
    }
    next(error);
});

const UserModel = mongoose.model("users",UserSchema);

module.exports = {
    UserModel
}