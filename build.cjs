const coffeeScriptPlugin = require('esbuild-coffeescript');
const { nodeExternalsPlugin } = require('esbuild-node-externals');
require('esbuild').build({
    entryPoints: ['lib/index.coffee'],
    bundle: true,
    outfile: 'dist.js',
    plugins: [coffeeScriptPlugin(), nodeExternalsPlugin()],
    platform: 'node'
});