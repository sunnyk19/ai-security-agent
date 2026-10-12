import { Body, Controller, Param, Post } from '@nestjs/common';
import { AiAnalysisService } from './ai-analysis.service.js';
import type { SecurityFinding } from '../security/security.types.js';
import type { VulnerabilityAnalysis } from './ai-analysis.types.js';

@Controller('repositories')
export class AiAnalysisController {
  constructor(private readonly analysis: AiAnalysisService) {}

  @Post(':owner/:repository/analyze-finding')
  analyzeFinding(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
    @Body() finding: SecurityFinding,
  ) {
    return this.analysis.analyze(owner, repository, finding);
  }
// 10086304175
  @Post(':owner/:repository/generate-fix')
  generateFix(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
    @Body()
    body: { finding: SecurityFinding; analysis: VulnerabilityAnalysis },
  ) {
    return this.analysis.generateFix(
      owner,
      repository,
      body?.finding,
      body?.analysis,
    );
  }
}