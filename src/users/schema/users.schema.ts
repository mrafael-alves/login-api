import * as mongoose from 'mongoose';
import * as bcrypt from 'bcrypt';

export const UsersSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    cpf: {
        type: String,
        required: false,
        unique: true,
        length: 11
    },
    cnpj: {
        type: String,
        required: false,
        unique: true,
        length: 14
    },
    role: {
        type: String,
        default: 'admin',
    },
    resetPasswordToken: {
        type: String,
        required: false,
    },
    resetPasswordExpires: {
        type: Date,
        required: false,
    },

});

UsersSchema.pre('save', async function(next) {
    try {
        if (!this.isModified('password')) {
            return next();
        }

        this['password'] = await bcrypt.hash(this['password'], 10);
    }   catch (err) {
        if (err instanceof Error) {
            next(err);
        } else {
            next(new Error('An unknown error occurred'));
        }
    }
});