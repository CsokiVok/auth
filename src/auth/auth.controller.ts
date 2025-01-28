import { Body, Controller, Get, Post, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { User } from '@prisma/client';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    try {
      return await this, this.authService.login(loginDto);
    } catch {
      throw new UnauthorizedException('Invalid email or password');
    }
  }

  @Get('me')
  @UseGuards(AuthGuard('bearer'))
  async me(@Req() req: Request) {
    const user = req.user as User;
    delete user.password;
    return user;
  }
}

