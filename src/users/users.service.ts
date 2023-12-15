import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { User } from './models/users.model';
import { AuthService } from 'src/auth/auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

interface ILogin {
    name: string;
    jwtToken: string;
    email: string
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
        return newUser.save();
    }

    public async login(loginDto: LoginDto): Promise<ILogin> {
        const user = await this.findByEmail(loginDto.email);
        const match = await this.checkPassword(loginDto.password, user);

        if (!match) {
            throw new NotFoundException('E-mail or password is invalid.');
        }

        const jwtToken = await this.authService.createAccessToken(user._id);

        return {name: user.name, jwtToken, email: user.email};
    }

    public async findAll(): Promise<User[]> {
        return this.usersModel.find();
    }

    private async findByEmail(email: string): Promise<User> {
        const user = await this.usersModel.findOne({email});
        if (!user) {
            throw new NotFoundException('Email not found.');
        }

        return user;
    }

    private async checkPassword(password: string, user: User): Promise<boolean> {        
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            throw new NotFoundException('Password not found.');
        }

        return match;
    }
}