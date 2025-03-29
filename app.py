from flask import Flask, request, render_template, redirect, url_for, send_file, jsonify, Response, abort
import os
import json
import configparser
import shutil
from collections import defaultdict
from analysis import clone_repository, is_valid_rust_project, save_results_csv, save_results_json, save_results_markdown, save_results_html
from analysis import analyze_project as analyze_code
from analysis import convert_to_markdown, convert_to_csv, convert_to_txt, convert_to_html
from ast_analysis import run_ast_analysis as analyze_ast
import logging
from typing import Dict, List
from logger_config import setup_logger

logger = setup_logger('app', 'logs/app.log')

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

def convert_to_markdown_ast(results: Dict[str, List[Dict]], files_analyzed: int) -> str:
    """Convert AST analysis results to markdown format."""
    if not results:
        return "No issues found in the analysis."
    
    markdown = f"# AST Analysis Report\n\n"
    markdown += f"**Files Analyzed:** {files_analyzed}\n"
    markdown += f"**Total Issues Found:** {sum(len(issues) for issues in results.values())}\n\n"
    
    # Group issues by severity
    severity_groups = {}
    for file_path, issues in results.items():
        for issue in issues:
            severity = issue['severity']
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append((file_path, issue))
    
    # Sort severities (Critical -> High -> Medium -> Low)
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    for severity in severity_order:
        if severity in severity_groups:
            markdown += f"## {severity} Severity Issues\n\n"
            for file_path, issue in severity_groups[severity]:
                markdown += f"### {file_path}:{issue['line']}\n\n"
                markdown += f"**Issue:** {issue['issue']}\n"
                markdown += f"**Category:** {issue['category']}\n"
                markdown += f"**Risk Score:** {issue['risk_score']:.1f}\n\n"
                markdown += "**Code:**\n```rust\n"
                markdown += f"{issue['code']}\n"
                markdown += "```\n\n"
                markdown += "**Context:**\n```rust\n"
                markdown += f"{issue['context']}\n"
                markdown += "```\n\n"
                if issue.get('fix_suggestion'):
                    markdown += "**Fix Suggestion:**\n```rust\n"
                    markdown += f"{issue['fix_suggestion']}\n"
                    markdown += "```\n\n"
                if issue.get('model_predictions'):
                    markdown += "**Model Predictions:**\n"
                    for key, value in issue['model_predictions'].items():
                        markdown += f"- {key}: {value}\n"
                    markdown += "\n"
                markdown += "---\n\n"
    
    return markdown

def convert_to_csv_ast(results: Dict[str, List[Dict]], files_analyzed: int) -> str:
    """Convert AST analysis results to CSV format."""
    if not results:
        return "No issues found in the analysis."
    
    # Create CSV header
    csv = "File,Line,Issue,Severity,Category,Risk Score,Code,Context,Fix Suggestion,Model Predictions\n"
    
    # Add each issue as a row
    for file_path, issues in results.items():
        for issue in issues:
            # Escape special characters in fields
            code = issue['code'].replace('"', '""')
            context = issue['context'].replace('"', '""')
            fix_suggestion = issue.get('fix_suggestion', '').replace('"', '""')
            model_predictions = str(issue.get('model_predictions', '')).replace('"', '""')
            
            csv += f'"{file_path}",{issue["line"]},"{issue["issue"]}","{issue["severity"]}",'
            csv += f'"{issue["category"]}",{issue["risk_score"]:.1f},"{code}","{context}",'
            csv += f'"{fix_suggestion}","{model_predictions}"\n'
    
    return csv

def convert_to_txt_ast(results: Dict[str, List[Dict]], files_analyzed: int) -> str:
    """Convert AST analysis results to plain text format."""
    if not results:
        return "No issues found in the analysis."
    
    text = "AST Analysis Report\n"
    text += "=" * 50 + "\n\n"
    text += f"Files Analyzed: {files_analyzed}\n"
    text += f"Total Issues Found: {sum(len(issues) for issues in results.values())}\n\n"
    
    # Group issues by severity
    severity_groups = {}
    for file_path, issues in results.items():
        for issue in issues:
            severity = issue['severity']
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append((file_path, issue))
    
    # Sort severities (Critical -> High -> Medium -> Low)
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    for severity in severity_order:
        if severity in severity_groups:
            text += f"\n{severity} Severity Issues\n"
            text += "-" * 50 + "\n\n"
            for file_path, issue in severity_groups[severity]:
                text += f"File: {file_path}:{issue['line']}\n"
                text += f"Issue: {issue['issue']}\n"
                text += f"Category: {issue['category']}\n"
                text += f"Risk Score: {issue['risk_score']:.1f}\n\n"
                text += "Code:\n"
                text += "-" * 20 + "\n"
                text += f"{issue['code']}\n"
                text += "-" * 20 + "\n\n"
                text += "Context:\n"
                text += "-" * 20 + "\n"
                text += f"{issue['context']}\n"
                text += "-" * 20 + "\n\n"
                if issue.get('fix_suggestion'):
                    text += "Fix Suggestion:\n"
                    text += "-" * 20 + "\n"
                    text += f"{issue['fix_suggestion']}\n"
                    text += "-" * 20 + "\n\n"
                if issue.get('model_predictions'):
                    text += "Model Predictions:\n"
                    for key, value in issue['model_predictions'].items():
                        text += f"- {key}: {value}\n"
                    text += "\n"
                text += "=" * 50 + "\n\n"
    
    return text

def convert_to_html_ast(results: Dict[str, List[Dict]], files_analyzed: int) -> str:
    """Convert AST analysis results to HTML format."""
    if not results:
        return "<html><body><h1>AST Analysis Report</h1><p>No issues found in the analysis.</p></body></html>"
    
    html = """<!DOCTYPE html>
                <html>
                <head>
                    <title>AST Analysis Report</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                        .issue {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                        .critical {{ border-left: 5px solid #dc3545; }}
                        .high {{ border-left: 5px solid #fd7e14; }}
                        .medium {{ border-left: 5px solid #ffc107; }}
                        .low {{ border-left: 5px solid #28a745; }}
                        pre {{ background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }}
                        code {{ font-family: Consolas, monospace; }}
                        .severity-section {{ margin: 30px 0; }}
                        .severity-header {{ background: #e9ecef; padding: 10px; border-radius: 5px; }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>AST Analysis Report</h1>
                        <p>Files Analyzed: {files_analyzed}</p>
                        <p>Total Issues Found: {total_issues}</p>
                    </div>
                """.format(
                    files_analyzed=files_analyzed,
                    total_issues=sum(len(issues) for issues in results.values())
                )
    
    # Group issues by severity
    severity_groups = {}
    for file_path, issues in results.items():
        for issue in issues:
            severity = issue['severity']
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append((file_path, issue))
    
    # Sort severities (Critical -> High -> Medium -> Low)
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    for severity in severity_order:
        if severity in severity_groups:
            html += f"""
    <div class="severity-section">
        <div class="severity-header">
            <h2>{severity} Severity Issues</h2>
        </div>"""
            
            for file_path, issue in severity_groups[severity]:
                severity_class = issue['severity'].lower()
                html += f"""
        <div class="issue {severity_class}">
            <h3>{file_path}:{issue['line']}</h3>
            <p><strong>Issue:</strong> {issue['issue']}</p>
            <p><strong>Category:</strong> {issue['category']}</p>
            <p><strong>Risk Score:</strong> {issue['risk_score']:.1f}</p>
            
            <h4>Code:</h4>
            <pre><code>{issue['code']}</code></pre>
            
            <h4>Context:</h4>
            <pre><code>{issue['context']}</code></pre>"""
                
                if issue.get('fix_suggestion'):
                    html += f"""
            <h4>Fix Suggestion:</h4>
            <pre><code>{issue['fix_suggestion']}</code></pre>"""
                
                if issue.get('model_predictions'):
                    html += """
            <h4>Model Predictions:</h4>
            <ul>"""
                    for key, value in issue['model_predictions'].items():
                        html += f"<li><strong>{key}:</strong> {value}</li>"
                    html += "</ul>"
                
                html += """
        </div>"""
            
            html += """
    </div>"""
    
    html += """
</body>
</html>"""
    
    return html

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
    """Handle AST analysis requests."""
    try:
        # Get full project path
        project_path = os.path.join(PROJECTS_DIR, project_subpath)
        if not os.path.exists(project_path):
            logger.error(f"Project path not found: {project_path}")
            if request.method == "POST":
                return jsonify({"error": f"Path {project_subpath} does not exist"}), 404
            return render_template("error.html", error=f"Path {project_subpath} does not exist")

        # Check if the path is a directory
        if not os.path.isdir(project_path):
            logger.error(f"Path is not a directory: {project_path}")
            if request.method == "POST":
                return jsonify({"error": f"Path {project_subpath} is not a directory"}), 400
            return render_template("error.html", error=f"Path {project_subpath} is not a directory")

        # Check for Rust files
        rust_files = []
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.rs'):
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        rust_files.append(file_path)

        if not rust_files:
            logger.warning(f"No Rust files found in {project_path}")
            if request.method == "POST":
                return jsonify({"error": "No Rust files found in the project"}), 404
            return render_template("error.html", error="No Rust files found in the project")

        # Generate safe filename for the report
        safe_name = project_subpath.replace('/', '_')
        base_filename = f"{safe_name}_ast_report"
        json_path = os.path.join(REPORTS_DIR, f"{base_filename}.json")
        
        # Run AST analysis
        logger.info(f"Running AST analysis on {project_path}")
        try:
            results, files_analyzed = analyze_ast(project_path)
            os.makedirs(REPORTS_DIR, exist_ok=True)
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            logger.error(f"AST analysis failed: {e}")
            if request.method == "POST":
                return jsonify({"error": f"Failed to generate AST report: {str(e)}"}), 500
            return render_template("error.html", error=f"Failed to generate AST report: {str(e)}")
        
        if not results:
            logger.warning(f"No results found for {project_path}")
            if request.method == "POST":
                return jsonify({"error": "No results found"}), 404
            return render_template("ast_report.html", 
                                project_subpath=project_subpath,
                                results=[],
                                chart_data=prepare_chart_data([]))
            
        # Save results to JSON file
        os.makedirs(REPORTS_DIR, exist_ok=True)
        try:
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"AST analysis results saved to {json_path}")
        except Exception as e:
            logger.error(f"Failed to save results to {json_path}: {e}")
            if request.method == "POST":
                return jsonify({"error": f"Failed to save results: {str(e)}"}), 500
            return render_template("error.html", error=f"Failed to save results: {str(e)}")

        # Convert results to a format suitable for the frontend
        formatted_results = []
        for file_path, file_results in results.items():
            for result in file_results:
                formatted_results.append({
                    'file': file_path,
                    'line': result.get('line', 0),
                    'issue': result.get('issue', ''),
                    'severity': result.get('severity', 'Unknown'),
                    'category': result.get('category', 'Unknown'),
                    'code': result.get('code', ''),
                    'context': result.get('context', ''),
                    'risk_score': result.get('risk_score', 0),
                    'fix_suggestion': result.get('fix_suggestion'),
                    'model_predictions': result.get('model_predictions', {})
                })

        # Prepare chart data for visualization
        chart_data = prepare_chart_data(formatted_results)

        # If it's a POST request, return JSON data
        if request.method == "POST" or request.headers.get("Accept") == "application/json":
            return jsonify({
                "status": "success",
                "results": formatted_results,
                "total_issues": len(formatted_results),
                "files_analyzed": files_analyzed,
                "report_path": json_path,
                "chart_data": chart_data
            })

        # For GET requests, render the template
        return render_template(
            "ast_report.html",
            project_subpath=project_subpath,
            results=formatted_results,
            chart_data=chart_data,
            files_analyzed=files_analyzed
        )

    except Exception as e:
        logger.error(f"Error in AST analysis: {e}")
        if request.method == "POST":
            return jsonify({"error": str(e)}), 500
        return render_template("error.html", error=str(e))

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
    """Download AST analysis report in specified format."""
    try:
        # Get the project path
        project_path = os.path.join("projects", project_name)
        if not os.path.exists(project_path):
            return "Project not found", 404
        
        # Run AST analysis
        results, files_analyzed = analyze_ast(project_path)
        
        # Convert results based on format
        if format == "json":
            content = json.dumps(results, indent=2)
            content_type = "application/json"
        elif format == "csv":
            content = convert_to_csv_ast(results, files_analyzed)
            content_type = "text/csv"
        elif format == "txt":
            content = convert_to_txt_ast(results, files_analyzed)
            content_type = "text/plain"
        elif format == "md":
            content = convert_to_markdown_ast(results, files_analyzed)
            content_type = "text/markdown"
        elif format == "html":
            content = convert_to_html_ast(results, files_analyzed)
            content_type = "text/html"
        else:
            return "Unsupported format", 400
        
        # Generate safe filename
        safe_name = project_name.replace('/', '_')
        filename = f"{safe_name}_ast_report.{format}"
        
        return Response(
            content,
            mimetype=content_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating AST report: {e}")
        return str(e), 500

@app.route("/delete/<path:project_subpath>", methods=["POST"])
def delete_project(project_subpath):
    """Delete a project or directory."""
    try:
        project_path = os.path.abspath(os.path.join(PROJECTS_DIR, project_subpath))
        
        # Security check to prevent directory traversal
        if not project_path.startswith(PROJECTS_DIR):
            return jsonify({"status": "error", "message": "Access denied"}), 403
            
        if not os.path.exists(project_path):
            return jsonify({"status": "error", "message": "Project not found"}), 404
            
        # Delete the directory and all its contents
        shutil.rmtree(project_path)
        return jsonify({"status": "success", "message": "Project deleted successfully"})
        
    except Exception as e:
        logger.error(f"Error deleting project: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)