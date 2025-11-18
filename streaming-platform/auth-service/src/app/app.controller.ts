import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AccessTokenGuard } from './guards/access-token.guard';
import { RefreshTokenGuard } from './guards/refresh-token.guard';

@Controller('auth')
export class AuthController {
  constructor(private service: AuthService) {}

  @Post('register')
  register(
    @Body('email') email: string,
    @Body('username') username: string,
    @Body('password') password: string,
  ) {
    return this.service.register(email, username, password);
  }

  @Post('login')
  login(@Body('email') email: string, @Body('password') password: string) {
    return this.service.login(email, password);
  }

  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  refresh(@Req() req: any) {
    const userId = req.user.sub;
    const rt = req.user.refreshToken;
    return this.service.refreshTokens(userId, rt);
  }

  @UseGuards(AccessTokenGuard)
  @Post('test')
  test() {
    return { msg: 'Access granted!' };
  }
}
