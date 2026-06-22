const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

// Create preview PNG from SVG
sharp('./preview.svg')
  .png()
  .toFile('preview.png')
  .then(() => console.log('Preview image generated: preview.png'))
  .catch(err => console.error('Error generating preview:', err));
