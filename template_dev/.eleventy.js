const pluginSass = require("eleventy-plugin-dart-sass");
const htmlmin = require("html-minifier");
const ejsPlugin = require("@11ty/eleventy-plugin-ejs");

module.exports = function (eleventyConfig) {
    eleventyConfig.addPlugin(ejsPlugin);
    eleventyConfig.addPassthroughCopy({ "langs/*": "static/language" });
    eleventyConfig.addPassthroughCopy({ "src/_fonts/*": "static/fonts" });
    eleventyConfig.addPlugin(pluginSass, {
        includePaths: [ 'src/_sass/*.sass'],
        outputDir: 'css',
        sassIndexFile: 'main.sass',
        outDir: 'templates',
        outPath: '/static/css',
        outFileName: 'main',
        outputStyle: "compressed",
        sourceMap:  { sourceMap: false }
    });
    eleventyConfig.addTransform("htmlmin", function(content, outputPath) {
        if(process.env.GTX_ENVIRONMENT !== 'production') {
            return content;
        }
        if( outputPath && outputPath.endsWith(".html") ) {
          let minified = htmlmin.minify(content, {
            useShortDoctype: true,
            removeComments: true,
            collapseWhitespace: true
          });
          return minified;
        }
    
        return content;
      });
     
    return {
        passthroughFileCopy: true,
        dir: {
            input: "src",
            output: "templates",
          },
    };
};