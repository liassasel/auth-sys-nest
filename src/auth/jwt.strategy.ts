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
            secretOrKey: 'Alessail2041', 
            ignoreExpiration: false
        });
    }

    async validate(payload: any) {

        if (!payload?.fp_hash) {
            throw new UnauthorizedException('Invalid Token')
        }

        const user = await this.prisma.user.findUnique({
            where: { id: payload.sub },
        });

        if (!user) {
            throw new UnauthorizedException('User not found')
        }

        // Validate fingerprint token

        const isValidFingerprint = await bcrypt.compare(
            payload.fp_hash,
            user.fingerPrintHash,
        );

        if (!isValidFingerprint) {
            throw new UnauthorizedException(' fingerprint does not match ');
        }

        return user;
    }
}