import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from './models/users.model';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';


interface LoginResponse {
    userData: {
      email: string;
      fullName: string;
    };
    accessToken: string;
  }
  
interface IUserData {
    userData: {
        _id: string;
        fullName: string;
        username: string;
        email: string;
        role: string;
    }
}

@Controller('user')
export class UsersController {
    constructor (private readonly usersService: UsersService) {}

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    public async register(@Body() registerDto: RegisterDto): Promise<User> {
        return this.usersService.register(registerDto);
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    public async login(@Body() loginDto: LoginDto): Promise<LoginResponse> {
        return this.usersService.login(loginDto);
    }

    @Get()
    @UseGuards(AuthGuard('jwt'))
    @HttpCode(HttpStatus.OK)
    public async findAll(): Promise<User[]> {
        return this.usersService.findAll();
    }

    @Get('me')
    @HttpCode(HttpStatus.OK)
    public async getMe(@Req() req: Request): Promise <IUserData> { 
        return this.usersService.getUserByToken(req);
    }

    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    public async forgotPassword(@Body('email') email: string) {
        return await this.usersService.forgotPassword(email)
    }

    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    public async resetPassword(@Body() body: {token: string, newPassword: string}): Promise<any> {
        return await this.usersService.resetPassword(body.token, body.newPassword)
    }

}