function analyzeProject(path) {
    // Create a file input for saving
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json,.csv,.html,.md';
    fileInput.nwsaveas = path.replace('/', '_') + '_report.json';
    
    // When a file is selected
    fileInput.addEventListener('change', function(e) {
        const savePath = e.target.value;
        if (savePath) {
            // Create form data
            const formData = new FormData();
            formData.append('save_path', savePath);
            
            // Ask for format
            const format = prompt('Choose format (json, csv, html, md):', 'json');
            if (format) {
                formData.append('format', format);
                
                // Submit the analysis request
                fetch('/analyze/' + path, {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert('Report saved successfully!');
                        window.location.href = '/analyze/' + path;
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => alert('Error: ' + error));
            }
        }
    });
    
    fileInput.click();
}

function runAstAnalysis(path) {
    // Create a file input for saving
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json';
    fileInput.nwsaveas = path.replace('/', '_') + '_ast_report.json';
    
    // When a file is selected
    fileInput.addEventListener('change', function(e) {
        const savePath = e.target.value;
        if (savePath) {
            // Create form data
            const formData = new FormData();
            formData.append('save_path', savePath);
            
            // Submit the analysis request
            fetch('/ast-analysis/' + path, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert('AST report saved successfully!');
                    window.location.href = '/ast-analysis/' + path;
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => alert('Error: ' + error));
        }
    });
    
    fileInput.click();
}

function browseProject(path) {
    window.location.href = "/browse/" + path;
}
