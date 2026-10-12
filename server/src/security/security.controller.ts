import { Body, Controller, Param, Post } from '@nestjs/common';
import { SecurityScannerService } from './security-scanner.service.js';

@Controller('repositories')
export class SecurityController {
  constructor(private readonly scanner: SecurityScannerService) {}

  @Post('test/scan')
  scanTestRepository() {
    const owner = process.env.TEST_REPOSITORY_OWNER ?? 'nestjs';
    const repository = process.env.TEST_REPOSITORY_NAME ?? 'nest';
    return this.scanner.scan(owner, repository);
  }

  @Post(':owner/:repository/scan')
  scanRepository(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
    @Body('branch') branch?: string,
  ) {
    // Keep the branch optional so existing API callers continue to scan the default branch.
    return this.scanner.scan(owner, repository, branch);
  }
}