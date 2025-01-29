import { Module } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';

@Module({
    controllers: [AuthController],
    providers: [AuthService, PrismaService, JwtService]
})
export class AuthModule {}