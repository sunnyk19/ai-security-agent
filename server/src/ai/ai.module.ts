import { Module } from '@nestjs/common';
import { GitHubModule } from '../github/github.module.js';
import { AiAnalysisController } from './ai-analysis.controller.js';
import { AiAnalysisService } from './ai-analysis.service.js';

@Module({
  imports: [GitHubModule],
  controllers: [AiAnalysisController],
  providers: [AiAnalysisService],
})
export class AiModule {}