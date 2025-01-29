import { IsEmail, IsString, MinLength } from "class-validator";

export class RegisterDto {
    @IsEmail()
    email: string

    @IsEmail()
    @MinLength(6)
    password: string
}