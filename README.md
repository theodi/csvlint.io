# CSVLint

CSVLint is an online validation tool for CSV files. It validates CSV files for conformity to standards, checks for missing or malformed data, and can validate against both [CSV on the Web (CSVW)](https://www.w3.org/TR/tabular-data-model/) and [Data Package](https://specs.frictionlessdata.io/data-package/) schema standards. CSVLint is developed and maintained by an open-source community, with hosting provided by the Open Data Institute (ODI).

## Features

- **Structure Validation**: Checks CSV files for structural issues, such as inconsistent row lengths, incorrect quoting, and malformed line endings.
- **Schema Validation**: Validates CSV data against specified schemas, including CSVW and Data Package standards, to ensure that data formats, types, and constraints are met.
- **Dialect Options**: Provides flexible dialect options for delimiters, quoting characters, line terminators, and other CSV parsing configurations.
- **URL and File Upload Validation**: Validates CSV files available via URL or directly uploaded.
- **Detailed Reporting**: Returns detailed feedback on validation results, including errors, warnings, and informational messages.
- **Privacy-Focused**: Does not store URLs or CSV content after validation. Instead, a one-way hash of URLs is stored to identify previously validated URLs without retaining identifiable data.

## Getting Started

### Prerequisites

Ensure that you have the following installed on your system:

- **Node.js** (version 14+ recommended)
- **MongoDB** (for storing validation reports)
- **[csvlint-api](https://github.com/theodi/csvlint-api)** (backend service to talk with the `csvlint` validation ruby gem)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/theodi/csvlint.io
   cd csvlint
   ```

2. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

3. **Install CSVLint API**:
   Refer to documentation [here](https://github.com/theodi/csvlint-api)

4. **Set up environment variables**:
   Copy `.env.example` to `.env` and set up the environment variables. Key variables include:
   - `PORT`: Port on which the server will run.
   - `MONGO_URI`: MongoDB URI for storing validation reports.
   - `CSVLINT_API`: URL for the CSVLint Ruby server (e.g., `http://localhost:4567/validate`).
   - `HOST`: Base URL for accessing the validation service (e.g., `https://csvlint.io`).

5. **Start the Node.js server**:
   ```bash
   npm start
   ```

### Usage

#### Web Interface

Access the web interface by navigating to `https://csvlint.io` (or your configured `HOST` and `PORT`).

#### API

The CSVLint API can be used programmatically to validate CSV files via URLs or direct file uploads.

- **POST /validate**: Validates a CSV file from a URL or uploaded file.
- **GET /validate**: Validates a CSV from a URL and returns either a badge or JSON report based on `format` and `accept` headers.

Examples of API usage can be found in the [API Documentation](#api-documentation).

### API Documentation

#### Endpoint

- `POST /validate`: Validates a CSV file or URL.
- `GET /validate`: Validates a CSV file from a URL and can return a validation badge.

#### Parameters

- **csvUrl** (string): URL to the CSV file to validate.
- **schemaUrl** (string): URL to a JSON schema for validation (optional).
- **file** (file): CSV file upload (optional, if `csvUrl` is provided).
- **schema** (file): JSON schema file upload (optional).
- **dialect options**: Optional CSV dialect options, such as `delimiter`, `lineTerminator`, and `quoteChar`.

#### Responses

The API can return a JSON response or validation badge depending on the `format` query parameter or `accept` header.

Example of a validation report JSON:
```json
{
  "version": "0.2",
  "licence": "http://opendatacommons.org/licenses/odbl/",
  "validation": {
    "source": "http://example.com/mydata.csv",
    "schema": "http://example.com/myschema.json",
    "state": "invalid",
    "errors": [{ "type": "undeclared_header", "category": "structure" }]
  }
}
```

### Example Badge Embed Code

To embed a validation badge for a CSV, you can use the following HTML:
```html
<a href="https://csvlint.io/validate?csvUrl=http://example.com/mydata.csv">
  <img src="https://csvlint.io/validate?csvUrl=http://example.com/mydata.csv&format=svg" alt="Validation Badge">
</a>
```

## Privacy Policy

This service is privacy-focused and removes any identifiable information from validation reports. To view a detailed privacy policy, see [Privacy Policy](https://csvlint.io/privacy).

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature.
3. Submit a pull request for review.

## License

This project is licensed under the [MIT License](LICENSE).
