/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */
import { sanitize } from './ContentSantizer';
import { IIssueContext } from './IIssueContext';

const issuesUrl = `https://github.com/dotnet/vscode-dotnet-runtime/issues`;

export function formatIssueUrl(error: Error | undefined, context: IIssueContext): [ string, string ] {
    context.logger.dispose(); // Ensure log file is up to date

    const errorMessage = !error ? '' : `**Error Message:** ${ sanitize(error!.message) }
**Error Stack:** ${ error.stack === undefined ? '' : sanitize(error!.stack!) }`;
    const issueBody = `<!-- IMPORTANT: Please be sure to remove any private information before submitting. -->

**Repro steps:**

1.

${ errorMessage }`;

    const issueMessage = `The issue text was copied to the clipboard.  Please paste it into this window.

Please attach the log file located at ${ context.logger.getFileLocation() }. Note that this file may contain personal data.

Privacy Alert! The contents copied to your clipboard may contain personal data. Prior to posting to GitHub, please remove any personal data which should not be publicly viewable. https://privacy.microsoft.com/en-US/privacystatement`;
    const url = `${issuesUrl}/new?body=${encodeURIComponent(issueMessage)}`;
    return [url, issueBody];
}
