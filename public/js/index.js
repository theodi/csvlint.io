function toggleDialectOptions() {
  const dialectOptions = document.getElementById("dialectOptions");
  const toggleButton = document.querySelector(".toggle-dialect-btn");

  dialectOptions.classList.toggle("collapsed");

  if (dialectOptions.classList.contains("collapsed")) {
    toggleButton.textContent = "Show Dialect Options";
  } else {
    toggleButton.textContent = "Hide Dialect Options";
  }
}

function updateFileName(inputId, fileNameId) {
  const input = document.getElementById(inputId);
  const fileNameDisplay = document.getElementById(fileNameId);

  // Display the selected file name, or reset if no file is selected
  fileNameDisplay.textContent = input.files.length > 0 ? input.files[0].name : '';
  
  // Clear the corresponding URL field when a file is selected
  if (inputId === 'fileUploadCSV' && input.files.length > 0) {
    document.querySelector('input[name="csvUrl"]').value = '';
  } else if (inputId === 'fileUploadSchema' && input.files.length > 0) {
    document.querySelector('input[name="schemaUrl"]').value = '';
  }
}

function clearFileInput(inputId, fileNameId) {
  const input = document.getElementById(inputId);
  const fileNameDisplay = document.getElementById(fileNameId);
  input.value = '';
  fileNameDisplay.textContent = '';
}

// Add event listeners for URL inputs to clear file inputs when URL is entered
document.addEventListener('DOMContentLoaded', function() {
  const csvUrlInput = document.querySelector('input[name="csvUrl"]');
  const schemaUrlInput = document.querySelector('input[name="schemaUrl"]');
  const csvFileInput = document.getElementById('fileUploadCSV');
  const schemaFileInput = document.getElementById('fileUploadSchema');
  
  // Add event listeners for file inputs
  if (csvFileInput) {
    csvFileInput.addEventListener('change', function() {
      updateFileName('fileUploadCSV', 'csvFileName');
    });
  }
  
  if (schemaFileInput) {
    schemaFileInput.addEventListener('change', function() {
      updateFileName('fileUploadSchema', 'schemaFileName');
    });
  }
  
  // Add event listeners for URL inputs
  if (csvUrlInput) {
    csvUrlInput.addEventListener('input', function() {
      if (this.value.trim()) {
        clearFileInput('fileUploadCSV', 'csvFileName');
      }
    });
  }
  
  if (schemaUrlInput) {
    schemaUrlInput.addEventListener('input', function() {
      if (this.value.trim()) {
        clearFileInput('fileUploadSchema', 'schemaFileName');
      }
    });
  }
  
  // Add event listener for dialect options toggle
  const toggleDialectBtn = document.querySelector('.toggle-dialect-btn');
  if (toggleDialectBtn) {
    toggleDialectBtn.addEventListener('click', toggleDialectOptions);
  }
}); 