import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async register(email: string, username: string, password: string) {
    const hash = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        email,
        username,
        passwordHash: hash,
      },
    });

    const tokens = await this.issueTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) throw new UnauthorizedException('Invalid credentials');

    const tokens = await this.issueTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async refreshTokens(userId: string, rt: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access denied');

    const match = await bcrypt.compare(rt, user.hashedRt);
    if (!match) throw new ForbiddenException('Access denied');

    const tokens = await this.issueTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async issueTokens(userId: string, email: string) {
    const payload = { sub: userId, email };

    const [access, refresh] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: process.env.JWT_ACCESS_SECRET,
        expiresIn: '15m',
      }),
      this.jwt.signAsync(payload, {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: access,
      refresh_token: refresh,
    };
  }

  async updateRefreshToken(userId: string, rt: string) {
    const hash = await bcrypt.hash(rt, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }
}
