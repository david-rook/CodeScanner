from tree_sitter import Language

Language.build_library(
    'build/my-languages.so',
    [
        'tree-sitter-python',
        'tree-sitter-java',
        'tree-sitter-javascript',
        'tree-sitter-ruby'
    ]
)