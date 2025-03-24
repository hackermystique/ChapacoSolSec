from flask import Flask, request, render_template, redirect, url_for, send_file, jsonify
import os
import json
import configparser
from collections import defaultdict
from analysis import clone_repository, is_valid_rust_project, save_results_csv, save_results_json, save_results_markdown, save_results_html
from analysis import analyze_project as analyze_code
from ast_analysis import run_ast_analysis as analyze_ast

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECTS_DIR = os.path.join(BASE_DIR, "projects")
REPORTS_DIR = os.path.join(BASE_DIR, "json_reports")

def discover_git_repos(base_path="projects"):
    discovered = []
    for root, dirs, files in os.walk(base_path):
        if ".git" in dirs:
            git_path = os.path.join(root, ".git")
            config_path = os.path.join(git_path, "config")
            head_path = os.path.join(git_path, "HEAD")

            # Get remote URL
            url = "unknown"
            if os.path.exists(config_path):
                try:
                    config = configparser.ConfigParser()
                    config.read(config_path)
                    url = config.get('remote "origin"', "url", fallback="unknown")
                except Exception:
                    pass

            # Get branch and commit
            branch = "unknown"
            commit = "unknown"
            if os.path.exists(head_path):
                try:
                    with open(head_path, "r") as f:
                        head_content = f.read().strip()
                        if head_content.startswith("ref: "):
                            ref = head_content.replace("ref: ", "")
                            branch = ref.split("/")[-1]
                            ref_path = os.path.join(git_path, ref)
                            if os.path.exists(ref_path):
                                with open(ref_path, "r") as rf:
                                    commit = rf.read().strip()
                        else:
                            # Direct commit hash
                            commit = head_content
                            branch = "detached"
                except Exception:
                    pass

            discovered.append({
                "name": os.path.basename(root),
                "url": url,
                "branch": branch,
                "commit": commit,
                "path": os.path.relpath(root, base_path)
            })
    return discovered

def write_url_list(repos, filename="projects/urls.git"):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        urls = sorted(set(repo["url"] for repo in repos if repo.get("url") != "unknown"))
        with open(filename, "w") as f:
            for url in urls:
                f.write(f"{url}\n")
        return True
    except Exception as e:
        return False

def is_url_already_cloned(url, urls_file="projects/urls.git"):
    if not url or not os.path.exists(urls_file):
        return False
    try:
        with open(urls_file, "r") as f:
            return url in {line.strip() for line in f}
    except Exception:
        return False
    with open(urls_file, "r") as f:
        return url in f.read()

def prepare_chart_data(results):
    """Prepare data for ApexCharts visualization.
    
    Args:
        results: List of analysis results or dict of file-based results
        
    Returns:
        dict: Formatted chart data for severity, category, risk scores and validation types
    """
    chart_data = {
        'severity_dist': defaultdict(int),
        'category_dist': defaultdict(int),
        'risk_scores': [],
        'validation_types': defaultdict(int),
    }
    
    # Normalize AST analysis results from file-based to list format
    if isinstance(results, dict):
        issues = []
        for file_path, file_issues in results.items():
            if isinstance(file_issues, list):
                for issue in file_issues:
                    if isinstance(issue, dict):
                        issue['file_path'] = file_path
                        issues.append(issue)
        results = issues
    
    SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low']
    CATEGORIES = ['unsafe', 'validation', 'access', 'cpi', 'other']
    
    for result in results:
        if not isinstance(result, dict):
            continue
            
        # Extract and normalize severity
        severity = result.get('severity', 'Unknown')
        if severity not in SEVERITY_LEVELS:
            severity = 'Unknown'
        chart_data['severity_dist'][severity] += 1
        
        # Extract and categorize issue type
        category = result.get('category', 'Unknown')
        if category not in CATEGORIES:
            issue_text = str(result.get('issue', '')).lower()
            if 'unsafe' in issue_text:
                category = 'unsafe'
            elif any(word in issue_text for word in ['deserialize', 'validation']):
                category = 'validation'
            elif any(word in issue_text for word in ['account', 'signer']):
                category = 'access'
            elif 'cpi' in issue_text:
                category = 'cpi'
            else:
                category = 'other'
        chart_data['category_dist'][category] += 1
        
        # Calculate risk score based on severity
        severity_score_map = {
            'Critical': 10,
            'High': 7.5,
            'Medium': 5,
            'Low': 2.5,
            'Unknown': 5
        }
        risk_score = severity_score_map.get(severity, 5)
        
        # Add risk score data point
        chart_data['risk_scores'].append({
            'x': result.get('line', 0),
            'y': risk_score,
            'category': category
        })
        
        # Track validation types
        if result.get('required_checks'):
            for check in result['required_checks']:
                chart_data['validation_types'][str(check)] += 1
        elif category in ['validation', 'access', 'cpi']:
            default_checks = {
                'validation': 'Input Validation',
                'access': 'Signer Check',
                'cpi': 'Program ID Check'
            }
            chart_data['validation_types'][default_checks[category]] += 1

    return {
        'severity_chart': {
            'series': [chart_data['severity_dist'].get(level, 0) for level in SEVERITY_LEVELS],
            'labels': SEVERITY_LEVELS
        },
        'category_chart': {
            'series': list(chart_data['category_dist'].values()) or [0],
            'labels': list(chart_data['category_dist'].keys()) or ['None']
        },
        'risk_scatter_chart': {
            'series': [{
                'name': 'Risk Score',
                'data': chart_data['risk_scores'] or [{'x': 0, 'y': 0, 'category': 'None'}]
            }]
        },
        'validation_chart': {
            'series': list(chart_data['validation_types'].values()) or [0],
            'labels': list(chart_data['validation_types'].keys()) or ['None']
        }
    }



@app.route("/", methods=["GET", "POST"])
def upload_project():
    existing_repos = discover_git_repos(PROJECTS_DIR)
    if request.method == "POST":
        repo_url = request.form.get("repo_url")
        if repo_url:
            project_name = clone_repository(repo_url, PROJECTS_DIR)
            return redirect(url_for("list_projects"))
    return render_template("upload.html", existing_repos=existing_repos)

@app.route("/check-update/<path:project_subpath>", methods=["POST"])
def check_update(project_subpath):
    project_path = os.path.abspath(os.path.join(PROJECTS_DIR, project_subpath))

    # Security check to prevent directory traversal
    if not project_path.startswith(PROJECTS_DIR) or not os.path.isdir(project_path):
        return jsonify({"status": "error", "message": "Invalid project path"}), 403

    try:
        import subprocess
        # Fetch latest from remote
        subprocess.check_output(["git", "-C", project_path, "fetch"], stderr=subprocess.STDOUT)

        # Compare local and remote commit hashes
        local_commit = subprocess.check_output(["git", "-C", project_path, "rev-parse", "HEAD"]).decode().strip()
        remote_commit = subprocess.check_output(["git", "-C", project_path, "rev-parse", "@{u}"]).decode().strip()

        if local_commit == remote_commit:
            return jsonify({"status": "up-to-date", "message": "Already on latest commit."})
        else:
            return jsonify({"status": "update-available", "message": "New commit(s) available on remote."})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Git error: {e.output.decode().strip()}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
               
@app.route("/projects", methods=["GET"])
def list_projects():
    directories = [d for d in os.listdir(PROJECTS_DIR) if os.path.isdir(os.path.join(PROJECTS_DIR, d))]
    return render_template(
        "projects.html",
        directories=directories,
        current_path="",
        is_valid_project=False,
        path_parts=[],
        is_browsing=False
    )

@app.route("/browse/<path:project_subpath>", methods=["GET"])
def browse_directories(project_subpath):
    """Allows users to navigate directories until a valid Rust project is found."""
    project_path = os.path.abspath(os.path.join(PROJECTS_DIR, project_subpath))
    
    # Security check to prevent directory traversal
    if not project_path.startswith(PROJECTS_DIR):
        return "Access denied", 403
    
    if not os.path.isdir(project_path):
        return "Directory not found", 404

    # Get list of subdirectories
    subdirs = [d for d in os.listdir(project_path) if os.path.isdir(os.path.join(project_path, d))]
    
    # Check if current directory is a valid Rust project
    is_valid = is_valid_rust_project(project_path)
    
    # Get relative path for navigation breadcrumbs
    rel_path = os.path.relpath(project_path, PROJECTS_DIR)
    path_parts = rel_path.split(os.sep)
    
    return render_template(
        "projects.html",
        current_path=project_subpath,
        directories=subdirs,
        is_valid_project=is_valid,
        path_parts=path_parts,
        is_browsing=True
    )

@app.route("/analyze/<path:project_subpath>", methods=["GET", "POST"])
def analyze_project(project_subpath):
    header1 = ''
    # Create the absolute path, preserving any subdirectories in project_subpath
    project_path = os.path.abspath(os.path.join(PROJECTS_DIR, project_subpath))
    
    if not os.path.isdir(project_path):
        return "Project not found", 404

    results = analyze_code(project_path, analysis_depth="Intermediate")
    
    from collections import Counter
    
    # Extract and count SecurityScores from results
    score_values = []
    for r in results:
        try:
            score = int(r.get('SecurityScore', 0))
            score_values.append(score)
        except (ValueError, TypeError):
            continue
    score_distribution = dict(sorted(Counter(score_values).items()))
    
    # Handle save path if provided
    if request.method == "POST":
        save_path = request.form.get('save_path')
        report_format = request.form.get('format', 'json')
        
        if save_path:
            try:
                # Generate report in requested format
                if report_format == 'json':
                    save_results_json(results, save_path)
                elif report_format == 'csv':
                    save_results_csv(results, save_path)
                elif report_format == 'html':
                    save_results_html(results, save_path)
                elif report_format == 'md':
                    save_results_markdown(results, save_path)
                
                return jsonify({"status": "success", "message": f"Report saved to {save_path}"})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
    
    # Save default JSON report
    report_path = os.path.join(REPORTS_DIR, f"{project_subpath.replace('/', '_')}_report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)

    # Prepare chart data for ApexCharts
    chart_data = prepare_chart_data(results)

    return render_template(
        "report.html",
        header1=header1,
        results=results,
        project_name=project_subpath,
        chart_data=chart_data,
        score_distribution=score_distribution,
        score_labels=list(score_distribution.keys()),
        score_values=list(score_distribution.values())
    )

@app.route("/ast-analysis/<path:project_subpath>", methods=["GET", "POST"])
def run_ast_analysis(project_subpath):
    project_path = os.path.join(PROJECTS_DIR, project_subpath)
    if not os.path.exists(project_path):
        return f"Path {project_subpath} does not exist", 404
    header1 = "AST - "
    # Generate safe filename for the report
    safe_name = project_subpath.replace('/', '_')
    base_filename = f"{safe_name}_ast_report"
    json_path = os.path.join(REPORTS_DIR, f"{base_filename}.json")
    paname = os.path.join("projects", project_subpath, f"{base_filename}.json")
    path_name = os.path.relpath(paname)
    # Run the AST analyzer and save results
    try:
        results = analyze_ast(project_path)
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to generate AST report: {str(e)}"}), 500
    
    # Calculate statistics
    total_issues = 0
    critical_issues = 0
    files_analyzed = 0
    
    if results:
        files_analyzed = len(results.keys())
        for file_path, file_issues in results.items():
            for issue in file_issues:
                if isinstance(issue, dict) and 'error' not in issue:
                    total_issues += 1
                    if issue.get('severity', '').lower() == 'critical':
                        critical_issues += 1
                    
                    # Ensure all required fields are present
                    if 'category' not in issue:
                        if 'unsafe' in issue.get('issue', '').lower():
                            issue['category'] = 'unsafe'
                        elif any(word in issue.get('issue', '').lower() for word in ['deserialize', 'validation']):
                            issue['category'] = 'validation'
                        elif any(word in issue.get('issue', '').lower() for word in ['account', 'signer']):
                            issue['category'] = 'access'
                        elif 'cpi' in issue.get('issue', '').lower():
                            issue['category'] = 'cpi'
                        else:
                            issue['category'] = 'other'
                    
                    # Ensure code snippet is present and formatted
                    if 'code' in issue:
                        code_lines = issue['code'].split('\n')
                        if 'line' in issue and isinstance(issue['line'], int):
                            line_num = issue['line'] - 1
                            if 0 <= line_num < len(code_lines):
                                issue['code'] = code_lines[line_num].strip()
                        else:
                            issue['code'] = code_lines[0].strip()
                    
                    # Add missing validation info if not present
                    if 'missing_validation' not in issue and issue['category'] in ['validation', 'access', 'cpi']:
                        issue['missing_validation'] = {
                            'validation': 'Missing require! or assert! macro for validation',
                            'access': 'Missing owner or signer verification',
                            'cpi': 'Missing program ID verification'
                        }[issue['category']]
                    
                    # Ensure severity is present
                    if 'severity' not in issue:
                        issue['severity'] = 'High'  # Default severity
    
    # Prepare chart data
    chart_data = prepare_chart_data(results)
    
    # Flatten real issues for rendering (avoid false positives)
    flat_results = []
    if results:
        for file_path, file_issues in results.items():
            for issue in file_issues:
                if isinstance(issue, dict) and 'error' not in issue:
                    flat_results.append(issue)

    chart_data = prepare_chart_data(flat_results)

    return render_template("ast_report.html",
                        results=flat_results,
                        project_name=base_filename,
                        chart_data=chart_data,
                        total_issues=total_issues,
                        critical_issues=critical_issues,
                        files_analyzed=files_analyzed)
    

@app.route("/download-report/<format>/<path:project_name>", methods=["GET"])
def download_report(format, project_name):

    safe_name = project_name.replace('/', '_')
    base_filename = f"{safe_name}_report"
    json_path = os.path.join(REPORTS_DIR, f"{base_filename}.json")
    paname = os.path.join("projects", project_name, f"{base_filename}.json")
    path_name = os.path.relpath(paname)
    safe_name = project_name.replace('/', '_')
    base_filename = f"{safe_name}_report"
    

    print("json_path",json_path)
    # print("base_filename",base_filename)
    print("json_path",json_path)
    print("path_name",path_name)

    if not os.path.exists(json_path):
        return (
            f"Base JSON report not found for {project_name}. "
            "Make sure the analysis was run before downloading.",
            404
        )

    if format == "json":
        return send_file(json_path, as_attachment=True, download_name=f"{base_filename}.json")

    with open(json_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        return "Invalid JSON format. Expected a list of result dicts.", 500

    if format == "csv":
        return convert_to_csv(data, base_filename)
    elif format == "txt":
        return convert_to_txt(data, base_filename)
    elif format == "md":
        return convert_to_markdown(data, base_filename)
    elif format == "html":
        return convert_to_html(data, base_filename)
    else:
        abort(400, description=f"Unsupported format: {format}")

@app.route("/download-ast-report/<format>/<path:project_name>", methods=["GET"])
def download_ast_report(format, project_name):

    # json_path = os.path.join(REPORTS_DIR, f"{project_name}.json")
    # paname = os.path.join("projects", f"{project_name}.json")
    # path_name = os.path.relpath(paname)

    # safe_name = project_name.replace('/', '_')
    # base_filename = f"{project_name}_ast_report"
    json_path = os.path.join(REPORTS_DIR, f"{project_name}.json")
    paname = os.path.join("projects", f"{project_name}.json")
    path_name = os.path.relpath(paname)
    logging.debug(f"json_path{json_path}")
    logging.debug(f"paname {paname}")
    logging.debug(f"path_name {path_name}")

    if not os.path.exists(json_path):
        return (
            f"AST report not found for {project_name}. "
            "Please run the analysis first.",
            404
        )

    if format == "json":
        return send_file(json_path, as_attachment=True, download_name=f"{project_name}.json")

    with open(json_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        return "Invalid JSON format. Expected a dictionary of file results.", 500

    # Convert the nested dictionary structure to a flat list for export
    flat_data = []
    for file_path, issues in data.items():
        for issue in issues:
            if isinstance(issue, dict) and 'error' not in issue:
                issue['file'] = file_path
                flat_data.append(issue)

    if format == "csv":
        return convert_to_csv(flat_data, project_name)
    elif format == "txt":
        return convert_to_txt(flat_data, project_name)
    elif format == "md":
        return convert_to_markdown(flat_data, project_name)
    elif format == "html":
        return convert_to_html(flat_data, project_name)
    else:
        abort(400, description=f"Unsupported format: {format}")

    # Generate AST report if it doesn't exist
    if not os.path.exists(json_path):
        try:
            results = analyze_ast(os.path.join(PROJECTS_DIR, project_name))
            os.makedirs(REPORTS_DIR, exist_ok=True)
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to generate AST report: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)