/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'export',
    trailingSlash: true,
    basePath: '/frontend',
    assetPrefix: '/frontend',
    images: {
        unoptimized: true
    }
}

module.exports = nextConfig
