const pluginSass = require("eleventy-plugin-dart-sass");
module.exports = function (eleventyConfig) {
    eleventyConfig.addPassthroughCopy({ "langs/*": "static/language" });
    eleventyConfig.addPassthroughCopy({ "src/_fonts/*": "static/fonts" });
    eleventyConfig.addPlugin(pluginSass, {
        includePaths: [ 'src/_sass/*.sass'],
        outputDir: 'css',
        sassIndexFile: 'main.sass',
        outDir: 'templates',
        outPath: '/static/css',
        outFileName: 'main',
        sourceMap:  { sourceMap: false }
    });
    return {
        passthroughFileCopy: true,
        dir: {
            input: "src",
            output: "templates",
          },
    };
};