import React, { useState } from 'react';
import './App.css';

function App() {
  const [file, setFile] = useState(null);
  const [encStatus, setEncStatus] = useState('');
  const [encDownloadUrl, setEncDownloadUrl] = useState('');

  const [zipFile, setZipFile] = useState(null);
  const [decStatus, setDecStatus] = useState('');
  const [decDownloadUrl, setDecDownloadUrl] = useState('');

  const handleEncryptUpload = async () => {
    if (!file) {
      setEncStatus('Please select a text file.');
      return;
    }

    setEncStatus('Uploading...');
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://3.107.86.220:8080/api/files/encrypt', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) throw new Error('Upload failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      setEncDownloadUrl(url);
      setEncStatus('Encryption successful. Click below to download.');
    } catch (err) {
      console.error(err);
      setEncStatus('Encryption failed.');
    }
  };

  const handleDecryptUpload = async () => {
    if (!zipFile) {
      setDecStatus('Please select an encrypted zip file.');
      return;
    }

    setDecStatus('Uploading...');
    const formData = new FormData();
    formData.append('file', zipFile);

    try {
      const response = await fetch('http://3.107.86.220:8080/api/files/decrypt', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) throw new Error('Decryption failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      setDecDownloadUrl(url);
      setDecStatus('Decryption successful. Click below to download.');
    } catch (err) {
      console.error(err);
      setDecStatus('Decryption failed.');
    }
  };

  return (
    <div className="App">
      <h1>Encrypt & Decrypt Files</h1>

      {/* Encryption Section */}
      <section>
        <h2>🔐 Encrypt File</h2>
        <input type="file" accept=".txt" onChange={(e) => {
          setFile(e.target.files[0]);
          setEncStatus('');
          setEncDownloadUrl('');
        }} />
        <br /><br />
        <button onClick={handleEncryptUpload}>Encrypt</button>
        <p>{encStatus}</p>
        {encDownloadUrl && (
          <a href={encDownloadUrl} download="encrypted_package.zip">Download Encrypted File</a>
        )}
      </section>

      <hr style={{ margin: '40px 0' }} />

      {/* Decryption Section */}
      <section>
        <h2>🔓 Decrypt File</h2>
        <input type="file" accept=".zip" onChange={(e) => {
          setZipFile(e.target.files[0]);
          setDecStatus('');
          setDecDownloadUrl('');
        }} />
        <br /><br />
        <button onClick={handleDecryptUpload}>Decrypt</button>
        <p>{decStatus}</p>
        {decDownloadUrl && (
          <a href={decDownloadUrl} download="decrypted.txt">Download Decrypted File</a>
        )}
      </section>
    </div>
  );
}

export default App;
