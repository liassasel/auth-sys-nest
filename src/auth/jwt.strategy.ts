import { ExtractJwt, Strategy } from 'passport-jwt'
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private prisma: PrismaService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'clave-secreta-segura'
        });
    }

    async validate(payload: any) {
        const user = await this.prisma.user.findUnique({
            where: { id: payload.sub },
        });

        // Validate fingerprint token

        const fingerprintValid = await bcrypt.compare(
            payload.fingerprint,
            user.fingerPrintHash,
        );

        if (!user || !fingerprintValid) {
            throw new UnauthorizedException('Invalid Token');
        }

        return user;
    }
}