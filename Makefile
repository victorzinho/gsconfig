default: doc

doxygen:
	@doxygen doxygen.config

doc-serve: doxygen
	mkdocs serve

doc: doxygen
	mkdocs build
