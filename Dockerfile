# see https://pages.github.com/versions.json
FROM ruby:3.3.4

WORKDIR /app/

COPY Gemfile ./

RUN bundle install

COPY ./ ./

ENTRYPOINT ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0"]
