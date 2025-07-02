import { Body, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SigninUserDto } from './dto/signin-user.dto';
import { GlobalResponseDto } from '../globals/dtos/global.response.dto';
import { ApiController, Public } from '../globals/decorators/global.decorators';

@ApiController({
  prefix: '/users/auth',
  tagName: 'Users - Auth',
  isBearerAuth: false,
  // resource: ResourcesEnum.UsersAuth,
})
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post()
  async signin(@Body() body: SigninUserDto) {
    return new GlobalResponseDto(
      HttpStatus.OK,
      'Signin User',
      await this.authService.signIn(body.email, body.password),
    );
  }

  //
  // @Get()
  // findAll() {
  //   return this.authService.findAll();
  // }
  //
  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }
  //
  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }
  //
  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}
