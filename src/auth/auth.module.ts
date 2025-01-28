import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { TokenStrategy } from './token.strategy';

@Module({
  controllers: [AuthController],
  providers: [AuthService,PrismaService, TokenStrategy],
})
export class AuthModule {}
