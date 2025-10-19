import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState('READY'); // READY, SUBMITTING, SUCCESS, FAILED
  const [error, setError] = useState('');
  const [messageId, setMessageId] = useState('');

  const API_ENDPOINT = process.env.REACT_APP_API_ENDPOINT;

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    // Reset status when a new file is chosen
    setStatus('READY');
    setError('');
    setMessageId('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to upload.');
      return;
    }

    const reader = new FileReader();
    reader.readAsText(file);
    reader.onload = async () => {
      try {
        const fileContent = JSON.parse(reader.result);
        setStatus('SUBMITTING');
        setError('');

        // Construct the payload your backend submitter_lambda expects
        const payload = {
          iac_plan: fileContent,
          scan_id: `web-upload-${Date.now()}` // Add a scan_id as the backend may need it
        };

        const response = await axios.post(`${API_ENDPOINT}/scans`, payload);

        // On success, update the status and show the SQS message ID
        setStatus('SUCCESS');
        setMessageId(response.data.sqsMessageId);

      } catch (err) {
        console.error(err);
        setError('Upload failed. Please ensure the file is a valid JSON and the API is configured correctly.');
        setStatus('FAILED');
      }
    };
    reader.onerror = () => {
        setError('Error reading the file.');
        setStatus('FAILED');
    }
  };

  const getStatusMessage = () => {
    switch (status) {
      case 'SUBMITTING':
        return 'Submitting your file to the scanner...';
      case 'SUCCESS':
        return `✅ Scan request submitted successfully! (SQS Message ID: ${messageId})`;
      case 'FAILED':
        return `❌ ${error}`;
      default:
        return 'Select a Terraform JSON plan to submit.';
    }
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>Submit IaC Plan for Scanning</h1>
      </header>
      <main className="container">
        <div className="card">
          <form onSubmit={handleSubmit}>
            <input type="file" onChange={handleFileChange} accept=".json" />
            <button type="submit" disabled={!file || status === 'SUBMITTING'}>
              Submit for Scan
            </button>
          </form>
          <div className="status-bar">
            <p><strong>Status:</strong> {getStatusMessage()}</p>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;