import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { User } from './models/users.model';
import { AuthService } from 'src/auth/auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';
import * as nodemailer from 'nodemailer';

interface LoginResponse {
    userData: {
      email: string;
      fullName: string;
    };
    accessToken: string;
  }

interface UserDataResponse {
    userData: {
        _id: string;
        fullName: string;
        username: string;
        email: string;
        role: string;
    }
}

@Injectable()
export class UsersService {
    constructor(
        @InjectModel('User')
        private readonly usersModel: Model<User>,
        private readonly authService: AuthService,
    ) {}

    public async register(registerDto: RegisterDto): Promise<User> {
        const user = await this.findByEmail(registerDto.email);
       
        if (user) {
            throw new Error('This email is already in use');
        }
        const newUser = new this.usersModel(registerDto);
        const savedUser = await newUser.save();

        const userObject = savedUser.toObject();
        userObject._id = userObject._id.toString();
        delete userObject.password;
        delete userObject.__v;

        return userObject;
    }

    public async login(loginDto: LoginDto): Promise<LoginResponse> {
        const user = await this.findByEmail(loginDto.email);
        const match = await this.checkPassword(loginDto.password, user);

        if (!match) {
            throw new NotFoundException('E-mail or password is invalid');
        }

        const accessToken = await this.authService.createAccessToken(user._id);

        const response = {
            userData: {
                email: user.email,
                fullName: user.fullName
            },
            accessToken: accessToken
        };
        
        return response;
    }

    public async findAll(): Promise<User[]> {
        return this.usersModel.find();
    }

    public async getUserByToken(req: Request): Promise<UserDataResponse> {
        const token = this.authService.returnJwtExtractor()(req);
        const decoded = this.authService.decodeToken(token);

        const user = await this.usersModel.findById(decoded.userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const response = {
            userData: {
                _id: user._id.toString(),
                fullName: user.fullName,
                username: user.username,
                email: user.email,
                role: user.role
            }
        }

        return response;
    }

    public async forgotPassword(email: string): Promise<any> {
        const user = await this.findByEmail(email);
        if (!user) {
            throw new NotFoundException("This account does not exist");
        }

        const token = await this.authService.createAccessToken(user._id);
        console.log(token)
        const tokenExpiry = new Date(new Date().getTime() + 60 * 60 * 1000);

        await this.saveResetToken(user._id.toString(), token.toString(), tokenExpiry);
        await this.sendResetEmail(email, token.toString());
    }

    public async resetPassword(token: string, newPassword: string): Promise<any> {
        const decoded = this.authService.decodeToken(token);
        const user = await this.usersModel.findById(decoded.userId);
        console.log('resetPassword Decoded: ', decoded);
        console.log('resetPassword User: ', user);
        if (!user) {
          throw new NotFoundException('User not found');
        }
    
        user.password = newPassword;
        await user.save();

        return { message: 'Password successfully updated' };
    }

    private async findByEmail(email: string): Promise<User | null> {
        return await this.usersModel.findOne({email}).exec();
    }

    private async checkPassword(password: string, user: User): Promise<boolean> {        
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            throw new Error('Invalid password');
        }

        return match;
    }

    private async saveResetToken (userID: string, token: string, expiry: Date) {
        const user = await this.usersModel.findById(userID);
        if (!user) {
            throw new Error('User not found');
        }
        console.log('saveResetToken token: ', token);

        user.resetPasswordToken = token;        
        user.resetPasswordExpires = expiry;
        await user.save();
        console.log('saveResetToken user.resetPasswordToken: ', user.resetPasswordToken);
    }

    private async sendResetEmail(email: string, token: string): Promise<void> {
        const transporter = nodemailer.createTransport({
          host: process.env.MAILGUN_SMTP_HOSTNAME,
          port: process.env.MAILGUN_PORT,
          secure: false,
          auth: {
            user: process.env.MAILGUN_USERNAME,
            pass: process.env.MAILGUN_DEFAULT_PASSWORD,
          },
        });
    
        const passwordResetUrl = `${process.env.FRONT_END_URL}/reset-password?token=${token}`
      
        const mailOptions = {
          from: 'rafa_al_m@hotmail.com',
          to: email,
          subject: 'Password Reset',
          html: `<p>Please use the following link to reset your password:</p><p><a href=${passwordResetUrl}>Reset Password</a></p>`,
        };
      
        await transporter.sendMail(mailOptions);
    }
      
}