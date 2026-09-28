import { readdir, readFile, appendFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const DAILY_MATRIX_SOURCES = ['cisa-kev', 'first-epss', 'microsoft-msrc-csaf', 'palo-alto-psirt-csaf', 'mozilla-mfsa-yaml'];
export function dailyReportsComplete(reports) {
  return reports.length === DAILY_MATRIX_SOURCES.length && DAILY_MATRIX_SOURCES.every(source => {
    const matches = reports.filter(report => report.source === source);
    return matches.length === 1 && matches[0].status === 'complete';
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const directory = process.argv[2];
  const reports = await Promise.all((await readdir(directory).catch(error => { if (error.code === 'ENOENT') return []; throw error; })).filter(name => name.endsWith('.json')).map(async name => JSON.parse(await readFile(`${directory}/${name}`, 'utf8'))));
  const complete = dailyReportsComplete(reports);
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `daily_complete=${complete}\n`);
  console.log(complete ? 'Every daily source completed fresh coverage.' : 'Daily cycle remains incomplete; committed progress will still be projected.');
}
