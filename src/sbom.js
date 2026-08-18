const crypto = require('crypto');

function purl(ecosystem, name, version) {
  const type = ecosystem === 'npm' ? 'npm' : 'composer';
  const encodedName = name.includes('/') ? name.split('/').map(encodeURIComponent).join('/') : encodeURIComponent(name);
  return `pkg:${type}/${encodedName}@${encodeURIComponent(version || '0.0.0')}`;
}

function toComponents(ecosystem, packages) {
  return (packages || []).map((p) => ({
    type: 'library',
    name: p.name,
    version: String(p.version || 'unknown'),
    purl: purl(ecosystem, p.name, p.version),
    licenses: p.license ? [{ license: { id: p.license } }] : [],
  }));
}

function buildSbom(projectName, licenses) {
  const components = [
    ...toComponents('npm', licenses.npm && licenses.npm.packages),
    ...toComponents('composer', licenses.composer && licenses.composer.packages),
  ];

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'CodeScope', name: 'codescope', version: '1.0.0' }],
      component: { type: 'application', name: projectName || 'project' },
    },
    components,
  };
}

module.exports = { buildSbom };
