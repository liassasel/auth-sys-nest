import { Controller, Post, Body, Req, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { Request } from "express";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('register')
    async register(
        @Body() dto: RegisterDto,
        @Req() req: Request
    ) {
        const fingerprint = req.headers['user-agent'] + req.ip;
        return this.authService.register(dto, fingerprint);
    }

    @Post('login')
    async login(
        @Body() dto: LoginDto,
        @Req() req: Request
    ) {
        const fingerprint = req.headers['user-agent'] + req.ip;
        return this.authService.login(dto, fingerprint);
    }


    @Post('enable-2fa')
    async enable2FA(@Body() body: { userId: number }) {
        return this.authService.generateNew2FAQr(body.userId); // <-- Nombre de método corregido
}

    @Post('verify-2fa')
    async verify2FA(@Body() body: { refreshToken: string }, @Req() req: Request) {
        const fingerprint = req.headers['user-agent'] + req.ip;
        return this.authService.refreshToken(body.refreshToken, fingerprint)
    }
}