// module.exports = {
//   baseUrl: process.env.NODE_ENV === 'production'
//     ? '/'
//     : '/'
// }
module.exports = {
  publicPath: process.env.NODE_ENV === "production" ? "/" : "/",
};
