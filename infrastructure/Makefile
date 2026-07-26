.PHONY: clean install synth diff deploy destroy lint test

clean:
	rm -rf .venv cdk.out

install:
	poetry config virtualenvs.in-project true
	poetry install

synth:
	cdk synth

diff:
	cdk diff

deploy:
	cdk deploy --all --require-approval never

destroy:
	cdk destroy --all --force

lint:
	poetry run python -m py_compile cdk/app.py

test:
	poetry run pytest tests/ -v
