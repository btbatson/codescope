const fs = require('fs');
const path = require('path');

const KNOWN_LIBS = {
  react: 'React', 'react-dom': 'React DOM', 'react-native': 'React Native',
  expo: 'Expo', next: 'Next.js', vue: 'Vue', nuxt: 'Nuxt', svelte: 'Svelte',
  '@sveltejs/kit': 'SvelteKit', typescript: 'TypeScript', tailwindcss: 'Tailwind CSS',
  express: 'Express', fastify: 'Fastify', koa: 'Koa', '@nestjs/core': 'NestJS',
  jest: 'Jest', vitest: 'Vitest', mocha: 'Mocha', eslint: 'ESLint', prettier: 'Prettier',
  webpack: 'Webpack', vite: 'Vite', rollup: 'Rollup', esbuild: 'esbuild',
  'styled-components': 'styled-components', graphql: 'GraphQL', apollo: 'Apollo',
  prisma: 'Prisma', mongoose: 'Mongoose', sequelize: 'Sequelize', typeorm: 'TypeORM',
  axios: 'Axios', redux: 'Redux', '@reduxjs/toolkit': 'Redux Toolkit', zustand: 'Zustand',
  electron: 'Electron', '@tauri-apps/cli': 'Tauri', '@tauri-apps/api': 'Tauri',
  jquery: 'jQuery', lodash: 'Lodash', d3: 'D3.js', three: 'Three.js',
  socket_io: 'Socket.IO', 'socket.io': 'Socket.IO', firebase: 'Firebase',
  supabase: 'Supabase', '@supabase/supabase-js': 'Supabase',
  'react-native-track-player': 'React Native Track Player',
  'react-navigation': 'React Navigation', '@react-navigation/native': 'React Navigation',
};

const PY_FRAMEWORKS = {
  flask: 'Flask', django: 'Django', fastapi: 'FastAPI', numpy: 'NumPy',
  pandas: 'Pandas', requests: 'Requests', pytest: 'pytest', torch: 'PyTorch',
  tensorflow: 'TensorFlow', scipy: 'SciPy', 'scikit-learn': 'scikit-learn',
};

function detectNpmStack(rootDir) {
  const pkgPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(pkgPath)) return [];
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const found = new Set();
    for (const key of Object.keys(deps)) {
      if (KNOWN_LIBS[key]) found.add(KNOWN_LIBS[key]);
    }
    return [...found];
  } catch {
    return [];
  }
}

function detectPythonStack(rootDir) {
  const reqPath = path.join(rootDir, 'requirements.txt');
  if (!fs.existsSync(reqPath)) return [];
  try {
    const lines = fs.readFileSync(reqPath, 'utf8').split('\n');
    const found = new Set();
    for (const line of lines) {
      const name = line.trim().split(/[=<>~\[; ]/)[0].toLowerCase();
      if (PY_FRAMEWORKS[name]) found.add(PY_FRAMEWORKS[name]);
    }
    return [...found];
  } catch {
    return [];
  }
}

function projectName(rootDir) {
  const pkgPath = path.join(rootDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.name) return pkg.name;
    } catch {
      // fall through to directory name
    }
  }
  return path.basename(rootDir);
}

function detectStack(rootDir) {
  const frameworks = [...detectNpmStack(rootDir), ...detectPythonStack(rootDir)];
  return {
    name: projectName(rootDir),
    frameworks,
  };
}

module.exports = { detectStack };
