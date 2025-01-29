import { Injectable, UnauthorizedException, InternalServerErrorException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import * as speakeasy from "speakeasy";
import * as QRCode from "qrcode";
import { PrismaService } from "src/prisma.service";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService
    ) {}

    async register(dto: RegisterDto, fingerprint: string) {
        try {
            const salt = await bcrypt.genSalt();
            const hashedPassword = await bcrypt.hash(dto.password, salt);

            const twoFactorSecret = speakeasy.generateSecret({
                length: 20,
                name: encodeURIComponent(`SecureApp:${dto.email}`) 
            }).base32;

            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    password: hashedPassword,
                    salt, 
                    twoFactorSecret, 
                    fingerPrintHash: await bcrypt.hash(fingerprint, 10),
                    refreshToken: null
                }
            });

            const otpUrl = speakeasy.otpauthURL({
                secret: twoFactorSecret,
                label: `SecureApp:${user.email}`,
                issuer: "SecureApp",
                encoding: "base32"
            });
            const qrCode = await QRCode.toDataURL(otpUrl);

            const tokens = await this.generateTokens(user, fingerprint);

            return {
                id: user.id,
                email: user.email,
                qrCode,
                ...tokens
            };

        } catch (error) {
            console.error('[AUTH ERROR]', error);
            throw new InternalServerErrorException('Error en el registro');
        }
    }

    async login(dto: LoginDto, fingerprint: string) {
        const user = await this.prisma.user.findUnique({
            where: { email: dto.email },
            select: { 
                id: true,
                password: true,
                twoFactorSecret: true // <- Nombre exacto del campo
            }
        });
    
        if (!user || !(await bcrypt.compare(dto.password, user.password))) {
            throw new UnauthorizedException("Credenciales inválidas");
        }
    
        // Validar 2FA
        if (dto.twoFactorCode && !this.validate2FACode(user.twoFactorSecret, dto.twoFactorCode)) {
            throw new UnauthorizedException("Código 2FA inválido");
        }
    
        return this.generateTokens(user, fingerprint);
    }

    
    private async generateTokens(user: any, fingerprint: string) {
        const fpHash = await bcrypt.hash(fingerprint, 10);

        const accessToken = this.jwtService.sign(
            {
                sub: user.id,
                email: user.email,
                fp_hash: fpHash
            },
            {
                expiresIn: '15m',
                secret: process.env.JWT_SECRET
            }
        );

        const refreshToken = this.jwtService.sign(
            { sub: user.id },
            {
                expiresIn: '7d',
                secret: process.env.JWT_REFRESH_SECRET
            }
        );

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                refreshToken,
                fingerPrintHash: fpHash
            }
        });

        return { accessToken, refreshToken };
    }

    private validate2FACode(secret: string, code: string): boolean {
        return speakeasy.totp.verify({
            secret,
            encoding: "base32",
            token: code,
            window: 2
        });
    }

    async refreshToken(refreshToken: string, fingerprint: string) {
        const user = await this.prisma.user.findFirst({
            where: { refreshToken }
        });

        if (!user || !(await bcrypt.compare(fingerprint, user.fingerPrintHash))) {
            throw new UnauthorizedException('Token de refresh inválido');
        }

        return this.generateTokens(user, fingerprint);
    }

    async validateUser(email: string, password: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
            select: { id: true, email: true, password: true }
        });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return null;
        }

        return user;
    }

    async generateNew2FAQr(userId: number) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId }
        });

        if (!user) throw new UnauthorizedException('Usuario no encontrado');

        const otpUrl = speakeasy.otpauthURL({
            secret: user.twoFactorSecret,
            label: `SecureApp:${user.email}`,
            issuer: "SecureApp",
            encoding: "base32"
        });

        return QRCode.toDataURL(otpUrl);
    }
}