import os
import sys
import json
from tree_sitter import Parser
from tree_sitter_languages import get_language

LANGUAGES = {
    '.java': 'java',
    '.js': 'javascript',
    '.py': 'python'
}

def detect_language(file_path):
    ext = os.path.splitext(file_path)[1]
    return LANGUAGES.get(ext)

def parse_code(code, language):
    parser = Parser()
    parser.set_language(get_language(language))
    return parser.parse(code)

def node_to_dict(node, source_code):
    return {
        'type': node.type,
        'start_point': node.start_point,
        'end_point': node.end_point,
        'text': source_code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore'),
        'children': [node_to_dict(child, source_code) for child in node.children]
    }

def summarize_symbols(language, node, source_code, symbols):
    def get_text(n):
        return source_code[n.start_byte:n.end_byte].decode('utf-8')

    if language == 'java':
        if node.type == 'class_declaration':
            name = node.child_by_field_name('name')
            if name:
                symbols['classes'].append({'name': get_text(name), 'start': node.start_point})
        elif node.type == 'method_declaration':
            name = node.child_by_field_name('name')
            if name:
                symbols['functions'].append({'name': get_text(name), 'start': node.start_point})
        elif node.type == 'import_declaration':
            symbols['imports'].append({'text': get_text(node), 'start': node.start_point})
        elif node.type == 'variable_declarator':
            name = node.child_by_field_name('name')
            if name:
                symbols['variables'].append({'name': get_text(name), 'start': node.start_point})

    elif language == 'javascript':
        if node.type == 'function_declaration':
            name = node.child_by_field_name('name')
            if name:
                symbols['functions'].append({'name': get_text(name), 'start': node.start_point})
        elif node.type == 'class_declaration':
            name = node.child_by_field_name('name')
            if name:
                symbols['classes'].append({'name': get_text(name), 'start': node.start_point})
        elif node.type == 'import_declaration':
            symbols['imports'].append({'text': get_text(node), 'start': node.start_point})
        elif node.type == 'lexical_declaration':
            kind = get_text(node.children[0])
            for child in node.children:
                if child.type == 'variable_declarator':
                    name = child.child_by_field_name('name')
                    if name:
                        target = 'constants' if kind == 'const' else 'variables'
                        symbols[target].append({'name': get_text(name), 'start': child.start_point})

    for child in node.children:
        summarize_symbols(language, child, source_code, symbols)

def build_project_ast(project_root):
    project_ast = {
        'type': 'Project',
        'source_dir': project_root,
        'files': [],
        'symbols': {
            'classes': [], 'functions': [], 'imports': [],
            'constants': [], 'variables': []
        }
    }

    for root, _, files in os.walk(project_root):
        for filename in files:
            ext = os.path.splitext(filename)[1]
            if ext not in LANGUAGES:
                continue

            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, project_root)
            language = detect_language(full_path)

            try:
                with open(full_path, 'rb') as f:
                    code = f.read()
                tree = parse_code(code, language)
                ast = node_to_dict(tree.root_node, code)

                # Extract symbols
                symbols = {k: [] for k in project_ast['symbols']}
                summarize_symbols(language, tree.root_node, code, symbols)

                project_ast['files'].append({
                    'path': rel_path,
                    'language': language,
                    'ast': ast
                })

                for k in symbols:
                    for s in symbols[k]:
                        s['file'] = rel_path
                        project_ast['symbols'][k].append(s)

                print(f"✔ Parsed: {rel_path}")
            except Exception as e:
                print(f"❌ Failed to parse {rel_path}: {e}")

    return project_ast

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_asts.py <project_dir>")
        sys.exit(1)

    source_dir = sys.argv[1]
    ast = build_project_ast(source_dir)

    with open("project.ast.json", "w") as f:
        json.dump(ast, f, indent=2)

    print("\n✅ project.ast.json written.")
