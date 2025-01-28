import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { hash } from 'argon2';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UsersService {
  constructor(private db: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    const hashedPw = await hash(createUserDto.password);
    const newUser =  await this.db.user.create({
      data: {
        ...createUserDto,
        password: hashedPw,
      },
    });
    delete newUser.password;
    return newUser;
  }

  findAll() {
    return `This action returns all users`;
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
