import { Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import * as speakeasy from "speakeasy";
import * as QRCode from "qrcode";
import { PrismaService } from "src/prisma.service";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService) {}

    // register user with hash password

    async register(email: string, password: string) {
        const hashedPassword = await bcrypt.hash(password, 10);
        return this.prisma.user.create({
            data: { email, password: hashedPassword },
        });
    }

    // validate credentials

    async validateUser(email: string, password: string) {
        const user = await this.prisma.user.findUnique({ where: { email }});
        if (user && await bcrypt.compare(password, user.password)) {
            return user;
        }
        return null;
    }

    // Generate Tokem with JWT and FingerPrint

    async generateTokens(user: any, fingerprint: string) {
        // Access Token 15 min
        const accessToken = this.jwtService.sign(
            {
                syb: user.id,
                email: user.email,
                fingerprint: await bcrypt.hash(fingerprint, 10) // Fingerprint hash token
            },
            { expiresIn: '15m' }
        );

        // Refresh token (7 days)

        const refreshToken = this.jwtService.sign(
            { sub: user.id },
            { expiresIn: '7d' },
        );

        // Store refreshToken + fingerPrint hashed in DB

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                refreshToken: await bcrypt.hash(refreshToken, 10),
                fingerPrintHash: await bcrypt.hash(fingerprint, 10),
            },
        });

        return { accessToken, refreshToken };
    }

    // Generate 2FA Secret and QR

    async generateTwoFactorSecret(userId: number) {
        const secret = speakeasy.generateSecret ({ name: 'Secure App' });
        await this.prisma.user.update({
            where: { id: userId },
            data: {
                TwoFactorSecret: secret.base32
            },
        });
        return QRCode.toDataURL(secret.otpauth_url); // QR code
    }

    // Validate 2FA Token

    async validateTwoFactorCode(userId: number, code: string) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        return speakeasy.totp.verify({
            secret: user.TwoFactorSecret,
            encoding: 'base32',
            token: code,
            window: 2,
        });
    }

    // Refresh Token

    async refreshToken(refreshToken: string, fingerprint: string) {
        const user = await this.prisma.user.findFirst({
            where: { refreshToken: await bcrypt.hash(refreshToken, 10) },
        });

        if (!user || !bcrypt.compareSync(fingerprint, user.fingerPrintHash)) {
            throw new UnauthorizedException('Invalid refresh token or fingerprint');
        }

        // Generate new tokens and refresh token in DB
        
        return this.generateTokens(user, fingerprint)
    }
}