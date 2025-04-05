// Configure Cloudinary (update with your Cloudinary credentials)
cloudinary.config({
    cloud_name: process.env.CLOUDNAME,
    api_key: process.env.APIKEY,
    api_secret: process.env.APISECRET
  });

  module.exports = clou