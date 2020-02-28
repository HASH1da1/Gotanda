const path = require('path')

module.exports = {
    mode: 'development',
    entry: './src/index.js',
    output: {
        filename: "background.js",
        path: path.join(__dirname, 'dist')
    }
};