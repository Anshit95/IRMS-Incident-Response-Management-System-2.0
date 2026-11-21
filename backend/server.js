const app = require('./app');

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`IRMS Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  if (!process.env.GEMINI_API_KEY && !process.env.OPENAI_API_KEY) {
    console.log('AI Mode: Enterprise Cognitive Defense Engine Active');
  } else {
    console.log('AI Mode: Live Cloud AI Active');
  }
});
