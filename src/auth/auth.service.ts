import { Injectable } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { PrismaService } from 'src/prisma.service';
import { verify } from 'argon2';
import * as crypro from 'node:crypto';

@Injectable()
export class AuthService {
    constructor(private db: PrismaService) { }

    async login(loginDto: LoginDto) {
        let user = await this.db.user.findUniqueOrThrow({
            where: {
                email: loginDto.email
            }
        });
        if (await verify(user.password, loginDto.password)) {
            return await this.db.token.create({
                data: {
                    token: crypro.randomBytes(32).toString('hex'),
                    user: { connect: { id: user.id } }
                }
            })
        }
        else {
            throw new Error('Invalid pass');
        }
    }
}
