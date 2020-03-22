.PHONY: serve serve-drafts bundle

serve:
	bundle exec jekyll serve --host 0.0.0.0

serve-drafts:
	bundle exec jekyll serve --host 0.0.0.0 --drafts

bundle:
	bundle install
