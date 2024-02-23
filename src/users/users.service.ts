import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { User } from './models/users.model';
import { AuthService } from 'src/auth/auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';
import * as nodemailer from 'nodemailer';
import * as fs from 'fs';
import { promisify } from 'util';

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
        cpf: string;
        cnpj: string;
        role: string;
    }
}

const readFileAsync = promisify(fs.readFile);

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
        if ((registerDto.cpf && registerDto.cnpj) || (!registerDto.cpf && !registerDto.cnpj)) {
            throw new BadRequestException('You must provide either CPF or CNPJ, not both.');
        }

        const newUser = new this.usersModel(registerDto);
        const savedUser = await newUser.save();

        const userObject = savedUser.toObject();
        userObject._id = userObject._id.toString();
        delete userObject.password;
        delete userObject.__v;

        await this.sendWelcomeEmail(userObject.email, userObject.fullName);


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
                cpf: user.cpf,
                cnpj: user.cnpj,
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
        const tokenExpiry = new Date(new Date().getTime() + 60 * 60 * 1000);

        await this.saveResetToken(user._id.toString(), token.toString(), tokenExpiry);
        await this.sendResetEmail(email, token.toString());
    }

    public async resetPassword(token: string, newPassword: string): Promise<any> {
        const decoded = this.authService.decodeToken(token);
        const user = await this.usersModel.findById(decoded.userId);
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

        user.resetPasswordToken = token;        
        user.resetPasswordExpires = expiry;
        await user.save();
    }

    private async emailTransporter (): Promise<nodemailer.transporter> {
        const transporter = nodemailer.createTransport({
          service:'gmail',
          host: process.env.GOOGLE_HOSTNAME,
          port: process.env.GOOGLE_PORT,
          secure: false,
          auth: {
            user: process.env.GOOGLE_USER,
            pass: process.env.GOOGLE_PASS,
          },
        });

        return transporter;
    }

    private async sendResetEmail (email: string, token: string): Promise <void> {
        const transporter = await this.emailTransporter();

        const passwordResetUrl = `${process.env.FRONT_END_URL}/reset-password?token=${token}`
      
        const mailOptions = {
          from: `${process.env.GOOGLE_USER}`,
          to: email,
          subject: 'Recuperação de senha CCAuto',
          html: `<p>Por favor, utilize o link para recuperar sua senha de acesso.</p><p><a href=${passwordResetUrl}>Reset Password</a></p>`,
        };
      
        await transporter.sendMail(mailOptions);
    } 

    private async loadEmailTemplate (templateName: string): Promise<string> {
        const templatePath = `C:/Users/Rafael/Desktop/Projetos/nestjs-login/src/users/email-templates/welcome-template/${templateName}`;
        return await readFileAsync(templatePath, 'utf-8');
    }

    public async sendWelcomeEmail (email: string, fullName: string): Promise<void> {
        const transporter = await this.emailTransporter();
        const htmlContent = await this.loadEmailTemplate('welcome-template.html');
        const personalizedContent = htmlContent.replace('{{name}}', fullName);

        const mailOptions = {
            from: `${process.env.GOOGLE_USER}`,
            to: email,
            subject: 'Bem-vindo(a) ao CCAuto',
            html: personalizedContent,
          };

          await transporter.sendMail(mailOptions);
    }
        
}
      
