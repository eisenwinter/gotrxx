module.exports = function() {
    return {
      environment: process.env.GTX_ENVIRONMENT || "development"
    };
  };