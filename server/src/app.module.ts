import { Module } from '@nestjs/common';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { AiModule } from './ai/ai.module.js';
import { GitHubModule } from './github/github.module.js';
import { SecurityModule } from './security/security.module.js';

@Module({
  imports: [GitHubModule, SecurityModule, AiModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
