# Stage 1: build the React app
FROM node:22-alpine AS builder

WORKDIR /app

# Accept build arg for API URL (e.g. /api when proxied through nginx)
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

COPY package.json ./
RUN npm install --frozen-lockfile
COPY . .
RUN npm run build

# Stage 2: serve with nginx
FROM nginx:1.27-alpine AS production

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
