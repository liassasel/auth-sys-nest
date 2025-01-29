import { IsEmail, IsString, IsOptional } from "class-validator";

export class LoginDto {
    @IsEmail()
    email: string

    @IsString()
    password: string

    @IsOptional()
    @IsString()
    twoFactorCode?: string;

}