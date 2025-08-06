# Generating Database Schema Documentation

If a visual representation of the relationship between the various entities in
the database is required, documentation in different formats can be generated
with a number of third-party tools.

As the schema documentation is based on an already initialized database, a
running PostgreSQL server is required to generate a new documentation.

The documentation can be generated with
[postgresql_autodoc](https://github.com/cbbrowne/autodoc). Provided
`postgresql_autodoc` is running as the same user who created the database, it is
sufficient to execute the following command to generate the HTML documentation:

    postgresql_autodoc -t html -d gvmd

The PNG documentation can be created by creating a documentation in the `dot`
format and then using the `dot` command provided by
[GraphViz](https://www.graphviz.org/) to generate a PNG file:

    postgresql_autodoc -t dot -d gvmd
    dot -Tpng gvmd.dot > gvmd.png
