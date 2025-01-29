import { Controller, Post, Body, Req, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { Request } from "express";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('register')
    async register(@Body()body: { email: string; password: string }) {
        return this.authService.register(body.email, body.password);
    }

    @Post('login')
    async LoginDto(@Body() body: { email: string; password: string }, @Req() req: Request) {
        const user = await this.authService.validateUser(body.email, body.password)
        if (!user) throw new UnauthorizedException('Invalid Credentials')

        // Generate Fingerprint ej user-agent + IP
        const fingerprint = req.headers['user-agent'] + req.ip;

        return this.authService.generateTokens(user, fingerprint)
    }

    @Post('enable-2fa')
    async enable2FA(@Body() body: { userId: number }) {
        return this.authService.generateTwoFactorSecret(body.userId)
    }

    @Post('verify-2fa')
    async verify2FA(@Body() body: { refreshToken: string }, @Req() req: Request) {
        const fingerprint = req.headers['user-agent'] + req.ip;
        return this.authService.refreshToken(body.refreshToken, fingerprint)
    }
}