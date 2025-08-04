document.addEventListener("DOMContentLoaded", function () {
  // Fetch the examples.json file from the server
  fetch('/examples/examples.json')
    .then(response => response.json())
    .then(examples => {
      const tableBody = document.getElementById('examples-table-body');

      examples.forEach((example, index) => {
        // Convert relative paths to full URLs for validation API
        const fullCsvUrl = example.csvUrl.startsWith('/') ? 
          `${window.location.origin}${example.csvUrl}` : example.csvUrl;
        const fullSchemaUrl = example.schemaUrl && example.schemaUrl.startsWith('/') ? 
          `${window.location.origin}${example.schemaUrl}` : example.schemaUrl;
        
        // Build the validation URL with dialect options if provided
        const dialectParams = example.dialect ? `&${example.dialect}` : '';
        const schemaParam = fullSchemaUrl ? `&schemaUrl=${encodeURIComponent(fullSchemaUrl)}` : '';
        const validationUrl = `/validate?csvUrl=${encodeURIComponent(fullCsvUrl)}${schemaParam}${dialectParams}`;

        // Create table row
        const row = document.createElement('tr');

        // Example title and description
        const exampleCell = document.createElement('td');
        exampleCell.innerHTML = `<h3>${example.title}</h3><p>${example.description}</p>`;
        row.appendChild(exampleCell);

        // CSV and schema contents in the same cell
        const contentCell = document.createElement('td');
        contentCell.innerHTML = `
          <div class="file-content">
            <strong>CSV Content:</strong>
            <pre id="file-content-${index}"><code>Loading CSV content...</code></pre>
          </div>
        `;
        if (example.schemaUrl) {
          /*contentCell.innerHTML += `
            <div class="file-content">
              <strong>Schema Content:</strong>
              <pre id="schema-content-${index}"><code>Loading schema content...</code></pre>
            </div>
          `;*/
        }
        row.appendChild(contentCell);

        // Expected result
        const expectedResultCell = document.createElement('td');
        expectedResultCell.textContent = example.expectedResult;
        row.appendChild(expectedResultCell);

        // Validation badge link
        const actualResultCell = document.createElement('td');
        actualResultCell.classList.add('result');
        
        // Create the link element properly to avoid HTML encoding
        const link = document.createElement('a');
        link.href = validationUrl;
        link.target = '_blank';
        
        const img = document.createElement('img');
        img.className = 'validationImg';
        img.src = `${validationUrl}&format=svg`;
        img.alt = `Validation Badge for ${example.title}`;
        
        link.appendChild(img);
        actualResultCell.appendChild(link);
        row.appendChild(actualResultCell);

        // Add the row to the table body
        tableBody.appendChild(row);

        // Fetch the CSV file content and display it using the new route
        fetch(example.csvUrl)
          .then(response => response.text())
          .then(data => {
            document.getElementById(`file-content-${index}`).textContent = data;
          })
          .catch(error => {
            console.error('Error loading CSV content:', error);
            document.getElementById(`file-content-${index}`).textContent = 'Error loading CSV content.';
          });

        // Fetch the schema file content if schemaUrl is defined
        if (example.schemaUrl) {
          fetch(example.schemaUrl)
            .then(response => response.text())
            .then(data => {
              document.getElementById(`schema-content-${index}`).textContent = data;
            })
            .catch(error => {
              console.error('Error loading schema content:', error);
              document.getElementById(`schema-content-${index}`).textContent = 'Error loading schema content.';
            });
        }
      });
    })
    .catch(error => {
      console.error('Error loading examples:', error);
    });
}); 