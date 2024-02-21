import { IsEmail, IsNotEmpty, IsString, Length, MinLength } from "class-validator";

export class RegisterDto {
    @IsNotEmpty()
    @IsString()
    fullName: string;

    @IsNotEmpty()
    @IsString()
    username: string;

    @IsNotEmpty()
    @IsString()
    @IsEmail()
    email: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(5)
    password: string;

    @IsString()
    @Length(11)
    cpf: string;

    @IsString()
    @Length(14)
    cnpj: string;

    @IsString()
    role: string = 'admin';
}