# WAFIShield Documentation

This directory contains the source files for the WAFIShield GitHub Pages website.

## Local Development

To run the documentation site locally:

1. Install Jekyll and Bundler:
```
gem install jekyll bundler
```

2. Create a Gemfile if it doesn't exist:
```
source 'https://rubygems.org'
gem 'github-pages', group: :jekyll_plugins
gem 'jekyll-remote-theme'
```

3. Install dependencies:
```
bundle install
```

4. Run the Jekyll server:
```
bundle exec jekyll serve
```

5. Open your browser to `http://localhost:4000` to view the site.

## Directory Structure

- `index.md`: Home page content
- `api/`: API documentation for each component
- `assets/css/`: Custom styling
- `_config.yml`: Jekyll configuration
- `.nojekyll`: Tells GitHub Pages not to run the contents through Jekyll

## Publishing

The documentation is automatically published to GitHub Pages when changes are pushed to the main branch.
