FROM php:7.4-apache

# LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="Docker image for DVWA (Damn Vulnerable Web Application) honeypot"

ENV DEBIAN_FRONTEND=noninteractive

# Install PHP extensions required by DVWA and general utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    wget \
    unzip \
    libpng-dev \
    libjpeg-dev \
    libzip-dev \
    && docker-php-ext-install \
    mysqli \
    gd \
    zip \
    pdo pdo_mysql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy DVWA source code to the web root
# shortcut: tracks DVWA master, pin a commit if upstream breaks the build
ARG DVWA_REF=master
RUN git clone --depth 1 --branch ${DVWA_REF} https://github.com/digininja/DVWA.git /var/www/html/dvwa

# Configure Apache for DVWA (e.g., setting DocumentRoot, allowing .htaccess)
RUN echo "<Directory /var/www/html/dvwa>" >> /etc/apache2/sites-available/000-default.conf && \
    echo "  AllowOverride All" >> /etc/apache2/sites-available/000-default.conf && \
    echo "</Directory>" >> /etc/apache2/sites-available/000-default.conf && \
    a2enmod rewrite

# Set appropriate permissions for the DVWA web content
RUN chown -R www-data:www-data /var/www/html/dvwa/ \
    && chmod -R 777 /var/www/html/dvwa/hackable/uploads/ \
    && (chmod -R 777 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/ 2>/dev/null || true)

# Copy custom DVWA config (e.g., for database connection)
# You would need to create a config.inc.php that points to a separate database container
# COPY config.inc.php /var/www/html/dvwa/config/config.inc.php

# Expose the web server port
EXPOSE 80

# The php:apache image handles starting Apache, so no CMD needed