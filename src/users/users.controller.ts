import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from './models/users.model';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';

interface ILogin {
    name: string;
    jwtToken: string;
    email: string
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
    public async login(@Body() loginDto: LoginDto): Promise<ILogin> {
        return this.usersService.login(loginDto);
    }

    @Get()
    @UseGuards(AuthGuard('jwt'))
    @HttpCode(HttpStatus.OK)
    public async findAll(): Promise<User[]> {
        return this.usersService.findAll();
    }

}
