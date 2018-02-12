.PHONY: serve bundle

serve:
	bundle exec jekyll serve --host 0.0.0.0 --drafts

bundle:
	bundle install
